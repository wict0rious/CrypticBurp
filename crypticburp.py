# -*- coding: utf-8 -*-
# CrypticBurp - A really simple encryption/decryption Burp extension
# Templatized for mobile (or any other) app pentesting with custom app-layer encryption
# A wict0rious and sparky23172 joint venture :)

from burp import (IBurpExtender, ITab, IMessageEditorTabFactory, IMessageEditorTab,
                  IHttpListener)
from javax.swing import (JPanel, JLabel, JTextField, JComboBox, JCheckBox,
                         JButton, JScrollPane, JTextArea, JFileChooser,
                         BorderFactory, BoxLayout, JOptionPane)
from java.awt import GridBagLayout, GridBagConstraints, Insets, Font, BorderLayout, FlowLayout
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec, GCMParameterSpec
from java.util import Base64
import re
import json

class CryptoEngine:
    """Handles all encryption/decryption with configurable algorithms"""
    
    ALGORITHMS = [
        "AES/CBC/NoPadding",
        "AES/CBC/PKCS5Padding",
        "AES/CTR/NoPadding",
        "AES/ECB/NoPadding",
        "AES/ECB/PKCS5Padding",
        "AES/GCM/NoPadding",
        "DES/CBC/PKCS5Padding",
        "DESede/CBC/PKCS5Padding",
    ]
    
    ENCODINGS = ["Base64", "Base64-URLSafe", "Hex", "None"]
    
    PADDINGS = ["None", "Tab (0x09)", "Space (0x20)", "Null (0x00)", "PKCS7 (auto)"]
    
    KEY_FORMATS = ["ASCII", "Hex", "Base64"]
    
    def __init__(self):
        self.algorithm = "AES/CBC/NoPadding"
        self.key = ""
        self.iv = ""
        self.key_format = "ASCII"
        self.iv_same_as_key = True
        self.encoding = "Base64"
        self.custom_padding = "Tab (0x09)"
        self.key_spec = None
        self.iv_spec = None
        
    def set_config(self, algorithm, key, iv, key_format, iv_same_as_key, encoding, custom_padding):
        self.algorithm = algorithm
        self.key = key
        self.key_format = key_format
        self.iv_same_as_key = iv_same_as_key
        self.iv = key if iv_same_as_key else iv
        self.encoding = encoding
        self.custom_padding = custom_padding
        
        # Pre-create key and IV specs for efficiency
        try:
            key_bytes = self._format_key(self.key, self.key_format)
            iv_bytes = self._format_key(self.iv, self.key_format)
            algo_name = self.algorithm.split("/")[0]
            self.key_spec = SecretKeySpec(key_bytes, algo_name)
            if "ECB" not in self.algorithm:
                self.iv_spec = IvParameterSpec(iv_bytes)

            def _hex(b):
                try:
                    return ''.join('%02x' % (x & 0xff) for x in b)
                except Exception:
                    return repr(b)

            print("[CryptoEngine] algo=%s  key=%d bytes  iv=%d bytes"
                  % (self.algorithm, len(key_bytes), len(iv_bytes)))
            print("[CryptoEngine] key hex: %s" % _hex(key_bytes))
            print("[CryptoEngine] iv  hex: %s" % _hex(iv_bytes))
        except Exception as e:
            print("[CryptoEngine] Error creating key specs: %s" % str(e))
            self.key_spec = None
            self.iv_spec = None
    
    def _format_key(self, key_str, format_type):
        """Convert key string to bytes for Java crypto, returns string for encode()"""
        if format_type == "Hex":
            # Convert hex to bytes
            hex_clean = key_str.replace(" ", "")
            byte_list = []
            for i in range(0, len(hex_clean), 2):
                byte_list.append(int(hex_clean[i:i+2], 16))
            return ''.join(chr(b) for b in byte_list).encode('latin-1')
        elif format_type == "Base64":
            decoder = Base64.getDecoder()
            decoded = decoder.decode(key_str)
            return ''.join(chr(b & 0xff) for b in decoded).encode('latin-1')
        else:
            # ASCII
            return key_str.encode('utf-8')
    
    def _remove_padding(self, data):
        """Remove custom padding from decrypted data, tries multiple methods"""
        if "NoPadding" not in self.algorithm:
            return data
        
        # Stream/authenticated modes never need block padding.
        if "CTR" in self.algorithm or "GCM" in self.algorithm:
            return data
        
        if not data:
            return data
        
        # First try the configured padding type
        if self.custom_padding == "Tab (0x09)":
            stripped = data.rstrip('\t')
            if stripped != data:
                return stripped
        elif self.custom_padding == "Space (0x20)":
            stripped = data.rstrip(' ')
            if stripped != data:
                return stripped
        elif self.custom_padding == "Null (0x00)":
            stripped = data.rstrip('\x00')
            if stripped != data:
                return stripped
        elif self.custom_padding == "PKCS7 (auto)":
            pad_len = ord(data[-1])
            if pad_len <= 16 and len(data) >= pad_len:
                return data[:-pad_len]
        
        # Fallback: try to auto-detect padding
        # Check for PKCS7 padding (last byte indicates padding length)
        last_byte = ord(data[-1])
        if last_byte <= 16 and len(data) >= last_byte:
            # Verify all padding bytes are the same
            padding_valid = all(ord(data[-(i+1)]) == last_byte for i in range(last_byte))
            if padding_valid:
                return data[:-last_byte]
        
        # Try stripping tabs
        stripped = data.rstrip('\t')
        if stripped != data:
            return stripped
        
        # Try stripping nulls
        stripped = data.rstrip('\x00')
        if stripped != data:
            return stripped
        
        return data
    
    def _add_padding(self, data_bytes):
        """Add custom padding to plaintext - common for custom mobile app specs"""
        if "NoPadding" not in self.algorithm:
            return data_bytes
        
        # Stream/authenticated modes never need block padding.
        if "CTR" in self.algorithm or "GCM" in self.algorithm:
            return data_bytes
        
        block_size = 16 if "AES" in self.algorithm else 8
        padding_len = block_size - (len(data_bytes) % block_size)
        if padding_len == 0:
            padding_len = block_size
        
        if self.custom_padding == "Tab (0x09)":
            pad_byte = b'\t'
        elif self.custom_padding == "Space (0x20)":
            pad_byte = b' '
        elif self.custom_padding == "Null (0x00)":
            pad_byte = b'\x00'
        elif self.custom_padding == "PKCS7 (auto)":
            pad_byte = bytes([padding_len])
        else:
            return data_bytes
        
        return data_bytes + (pad_byte * padding_len)
    
    def decrypt(self, ciphertext_encoded):
        """Decrypt data using current config"""
        if self.key_spec is None:
            print("[CryptoEngine] No key configured!")
            return None
        
        if not ciphertext_encoded:
            return None
            
        try:
            ciphertext_encoded = ciphertext_encoded.strip()
            
            # Quick check: if it looks like plaintext params, don't try to decrypt
            if ciphertext_encoded.startswith("&") or "userid=" in ciphertext_encoded:
                return None
            
            # Decode input based on encoding
            decoder = Base64.getDecoder()
            if self.encoding == "Base64-URLSafe":
                decoder = Base64.getUrlDecoder()
            
            if self.encoding in ["Base64", "Base64-URLSafe"]:
                # Validate base64 before decoding
                if not re.match(r'^[A-Za-z0-9+/=_-]+$', ciphertext_encoded.replace('\n', '').replace('\r', '')):
                    return None
                ciphertext = decoder.decode(ciphertext_encoded)
            elif self.encoding == "Hex":
                hex_clean = ciphertext_encoded.replace(" ", "")
                byte_list = []
                for i in range(0, len(hex_clean), 2):
                    byte_list.append(int(hex_clean[i:i+2], 16))
                ciphertext = bytes(bytearray(byte_list))
            else:
                ciphertext = ciphertext_encoded.encode('utf-8')
            
            # Create cipher and decrypt
            cipher = Cipher.getInstance(self.algorithm)
            
            if "GCM" in self.algorithm:
                gcm_spec = GCMParameterSpec(128, self.iv_spec.getIV())
                cipher.init(Cipher.DECRYPT_MODE, self.key_spec, gcm_spec)
            elif "ECB" in self.algorithm:
                cipher.init(Cipher.DECRYPT_MODE, self.key_spec)
            else:
                cipher.init(Cipher.DECRYPT_MODE, self.key_spec, self.iv_spec)
            
            plaintext_bytes = cipher.doFinal(ciphertext)
            
            # Convert to string
            plaintext = ''.join(chr(b & 0xff) for b in plaintext_bytes)
            
            # Remove padding
            return self._remove_padding(plaintext)
            
        except Exception as e:
            print("[CryptoEngine] Decrypt error: %s" % str(e))
            import traceback
            traceback.print_exc()
            return None
    
    def encrypt(self, plaintext):
        """Encrypt data using current config"""
        if self.key_spec is None:
            print("[CryptoEngine] No key configured!")
            return None
            
        try:
            # Add padding
            plaintext_bytes = plaintext.encode('utf-8')
            padded = self._add_padding(plaintext_bytes)
            
            # Create cipher and encrypt
            cipher = Cipher.getInstance(self.algorithm)
            
            if "GCM" in self.algorithm:
                gcm_spec = GCMParameterSpec(128, self.iv_spec.getIV())
                cipher.init(Cipher.ENCRYPT_MODE, self.key_spec, gcm_spec)
            elif "ECB" in self.algorithm:
                cipher.init(Cipher.ENCRYPT_MODE, self.key_spec)
            else:
                cipher.init(Cipher.ENCRYPT_MODE, self.key_spec, self.iv_spec)
            
            ciphertext = cipher.doFinal(padded)
            
            # Encode output
            if self.encoding == "Base64":
                encoder = Base64.getEncoder()
                return encoder.encodeToString(ciphertext)
            elif self.encoding == "Base64-URLSafe":
                encoder = Base64.getUrlEncoder()
                return encoder.encodeToString(ciphertext)
            elif self.encoding == "Hex":
                return ''.join('%02x' % (b & 0xff) for b in ciphertext)
            else:
                return ''.join(chr(b & 0xff) for b in ciphertext)
            
        except Exception as e:
            print("[CryptoEngine] Encrypt error: %s" % str(e))
            import traceback
            traceback.print_exc()
            return None

class BurpExtender(IBurpExtender, ITab, IMessageEditorTabFactory, IHttpListener):
    
    MARKER = "X-CrypticBurp-Enc"
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.crypto = CryptoEngine()
        
        # Config state
        self.config = {
            "target_host": "",
            "target_path": "",
            "decrypt_query": True,
            "decrypt_request_body": False,
            "decrypt_response_body": True,
            "request_body_type": "Raw",
            "request_body_field": "",
            "response_body_type": "Raw",
            "response_body_field": "",
            "algorithm": "AES/CBC/NoPadding",
            "key": "",
            "iv": "",
            "key_format": "ASCII",
            "iv_same_as_key": True,
            "encoding": "Base64",
            "padding": "Tab (0x09)"
        }
        
        callbacks.setExtensionName("CrypticBurp")
        
        # Build UI
        self._build_ui()
        
        callbacks.addSuiteTab(self)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerHttpListener(self)
        
        print("=" * 69)
        print(" CrypticBurp - A really simple encryption/decryption Burp extension")
        print("=" * 69)
        # lol
        print("")
        print(" Configure settings in the CrypticBurp tab, then:")
        print(" 1. Use 'Decrypted' tab on requests/responses to view plaintext")
        print(" 2. Edit and send, data auto encrypts before sending")
        print("")
    
    def _build_ui(self):
        """Build the configuration panel UI"""
        self._main_panel = JPanel(BorderLayout())
        
        # Config panel with scroll
        config_panel = JPanel()
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))
        config_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Target Section
        target_panel = JPanel(GridBagLayout())
        target_panel.setBorder(BorderFactory.createTitledBorder("Target"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        
        gbc.gridx = 0; gbc.gridy = 0
        target_panel.add(JLabel("Host:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        self._host_field = JTextField(30)
        self._host_field.setToolTipText("e.g., api.example.com")
        target_panel.add(self._host_field, gbc)
        
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0
        target_panel.add(JLabel("Path (optional):"), gbc)
        gbc.gridx = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        self._path_field = JTextField(20)
        self._path_field.setToolTipText("e.g., /api/v1/* (leave empty for all)")
        target_panel.add(self._path_field, gbc)
        
        config_panel.add(target_panel)
        
        # Locations Section
        locations_panel = JPanel(GridBagLayout())
        locations_panel.setBorder(BorderFactory.createTitledBorder("Decrypt/Encrypt Locations"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        
        # Query string
        gbc.gridx = 0; gbc.gridy = 0
        self._query_check = JCheckBox("Query String (GET params)", True)
        locations_panel.add(self._query_check, gbc)
        
        # Request body
        gbc.gridy = 1
        self._req_body_check = JCheckBox("Request Body", False)
        locations_panel.add(self._req_body_check, gbc)
        
        gbc.gridx = 1
        locations_panel.add(JLabel("Type:"), gbc)
        gbc.gridx = 2
        self._req_body_type = JComboBox(["Raw", "JSON field", "Form field"])
        locations_panel.add(self._req_body_type, gbc)
        gbc.gridx = 3
        locations_panel.add(JLabel("Field:"), gbc)
        gbc.gridx = 4
        self._req_body_field = JTextField(15)
        self._req_body_field.setToolTipText("Field name if JSON/Form, e.g., 'data' or 'payload'")
        locations_panel.add(self._req_body_field, gbc)
        
        # Response body
        gbc.gridx = 0; gbc.gridy = 2
        self._resp_body_check = JCheckBox("Response Body", True)
        locations_panel.add(self._resp_body_check, gbc)
        
        gbc.gridx = 1
        locations_panel.add(JLabel("Type:"), gbc)
        gbc.gridx = 2
        self._resp_body_type = JComboBox(["Raw", "JSON field", "Form field"])
        locations_panel.add(self._resp_body_type, gbc)
        gbc.gridx = 3
        locations_panel.add(JLabel("Field:"), gbc)
        gbc.gridx = 4
        self._resp_body_field = JTextField(15)
        locations_panel.add(self._resp_body_field, gbc)
        
        config_panel.add(locations_panel)
        
        # Crypto Settings Section
        crypto_panel = JPanel(GridBagLayout())
        crypto_panel.setBorder(BorderFactory.createTitledBorder("Crypto Settings"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        
        # Algorithm
        gbc.gridx = 0; gbc.gridy = 0
        crypto_panel.add(JLabel("Algorithm:"), gbc)
        gbc.gridx = 1; gbc.gridwidth = 2
        self._algo_combo = JComboBox(CryptoEngine.ALGORITHMS)
        crypto_panel.add(self._algo_combo, gbc)
        
        # Key
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1
        crypto_panel.add(JLabel("Key:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        self._key_field = JTextField(40)
        crypto_panel.add(self._key_field, gbc)
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0
        self._key_format = JComboBox(CryptoEngine.KEY_FORMATS)
        crypto_panel.add(self._key_format, gbc)
        
        # IV
        gbc.gridx = 0; gbc.gridy = 2
        crypto_panel.add(JLabel("IV:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        self._iv_field = JTextField(40)
        crypto_panel.add(self._iv_field, gbc)
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0
        self._iv_same_check = JCheckBox("Same as Key", True)
        self._iv_same_check.addActionListener(lambda e: self._iv_field.setEnabled(not self._iv_same_check.isSelected()))
        self._iv_field.setEnabled(False)
        crypto_panel.add(self._iv_same_check, gbc)
        
        # Encoding
        gbc.gridx = 0; gbc.gridy = 3
        crypto_panel.add(JLabel("Encoding:"), gbc)
        gbc.gridx = 1
        self._encoding_combo = JComboBox(CryptoEngine.ENCODINGS)
        crypto_panel.add(self._encoding_combo, gbc)
        
        # Padding
        gbc.gridx = 0; gbc.gridy = 4
        crypto_panel.add(JLabel("Custom Padding:"), gbc)
        gbc.gridx = 1
        self._padding_combo = JComboBox(CryptoEngine.PADDINGS)
        crypto_panel.add(self._padding_combo, gbc)
        
        config_panel.add(crypto_panel)
        
        # Buttons Section
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        apply_btn = JButton("Apply Config")
        apply_btn.addActionListener(lambda e: self._apply_config())
        button_panel.add(apply_btn)

        save_btn = JButton("Save Profile")
        save_btn.addActionListener(lambda e: self._save_profile())
        button_panel.add(save_btn)
        
        load_btn = JButton("Load Profile")
        load_btn.addActionListener(lambda e: self._load_profile())
        button_panel.add(load_btn)
        
        config_panel.add(button_panel)
        
        # Test Area
        test_panel = JPanel(GridBagLayout())
        test_panel.setBorder(BorderFactory.createTitledBorder("Test Area"))
        tgbc = GridBagConstraints()
        tgbc.fill = GridBagConstraints.BOTH
        tgbc.weighty = 1.0
        tgbc.insets = Insets(5, 5, 5, 5)

        self._test_input = JTextArea(8, 30)
        self._test_input.setFont(Font("Consolas", Font.PLAIN, 12))
        self._test_input.setLineWrap(True)
        self._test_input.setWrapStyleWord(True)
        tgbc.gridx = 0; tgbc.gridy = 0; tgbc.weightx = 1.0
        test_panel.add(JScrollPane(self._test_input), tgbc)

        test_btn = JButton("Test Decrypt ->")
        test_btn.addActionListener(lambda e: self._do_test_decrypt())
        tgbc.gridx = 1; tgbc.weightx = 0
        tgbc.fill = GridBagConstraints.NONE
        tgbc.anchor = GridBagConstraints.CENTER
        test_panel.add(test_btn, tgbc)

        self._test_output = JTextArea(8, 30)
        self._test_output.setFont(Font("Consolas", Font.PLAIN, 12))
        self._test_output.setLineWrap(True)
        self._test_output.setWrapStyleWord(True)
        self._test_output.setEditable(False)
        tgbc.gridx = 2; tgbc.weightx = 1.0
        tgbc.fill = GridBagConstraints.BOTH
        test_panel.add(JScrollPane(self._test_output), tgbc)

        config_panel.add(test_panel)
        
        # Add scroll pane
        scroll = JScrollPane(config_panel)
        self._main_panel.add(scroll, BorderLayout.CENTER)
    
    def _apply_config(self):
        """Apply current UI settings to crypto engine"""
        self.config["target_host"] = self._host_field.getText().strip()
        self.config["target_path"] = self._path_field.getText().strip()
        self.config["decrypt_query"] = self._query_check.isSelected()
        self.config["decrypt_request_body"] = self._req_body_check.isSelected()
        self.config["decrypt_response_body"] = self._resp_body_check.isSelected()
        self.config["request_body_type"] = str(self._req_body_type.getSelectedItem())
        self.config["request_body_field"] = self._req_body_field.getText().strip()
        self.config["response_body_type"] = str(self._resp_body_type.getSelectedItem())
        self.config["response_body_field"] = self._resp_body_field.getText().strip()
        self.config["algorithm"] = str(self._algo_combo.getSelectedItem())
        self.config["key"] = self._key_field.getText()
        self.config["iv"] = self._iv_field.getText()
        self.config["key_format"] = str(self._key_format.getSelectedItem())
        self.config["iv_same_as_key"] = self._iv_same_check.isSelected()
        self.config["encoding"] = str(self._encoding_combo.getSelectedItem())
        self.config["padding"] = str(self._padding_combo.getSelectedItem())
        
        # Update crypto engine
        self.crypto.set_config(
            self.config["algorithm"],
            self.config["key"],
            self.config["iv"],
            self.config["key_format"],
            self.config["iv_same_as_key"],
            self.config["encoding"],
            self.config["padding"]
        )
        
        print("[CrypticBurp] Config applied!")
        print("  Target: %s%s" % (self.config["target_host"], self.config["target_path"]))
        print("  Algorithm: %s" % self.config["algorithm"])
        print("  Locations: Query=%s, ReqBody=%s, RespBody=%s" % (
            self.config["decrypt_query"],
            self.config["decrypt_request_body"],
            self.config["decrypt_response_body"]
        ))
        
    def _do_test_decrypt(self):
        """Test decryption with input"""
        self._apply_config()
        input_text = self._test_input.getText().strip()
        if not input_text:
            self._test_output.setText("[No input]")
            return

        result = self.crypto.decrypt(input_text)
        if result:
            try:
                obj = json.loads(result)
                result = json.dumps(obj, indent=2, ensure_ascii=False)
            except:
                pass
            self._test_output.setText(result)
            self._test_output.setCaretPosition(0)
        else:
            self._test_output.setText("[Decryption failed - check settings]")

    def _save_profile(self):
        """Save current config to JSON file"""
        self._apply_config()
        
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Profile")
        if chooser.showSaveDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            filepath = chooser.getSelectedFile().getAbsolutePath()
            if not filepath.endswith(".json"):
                filepath += ".json"
            
            try:
                with open(filepath, 'w') as f:
                    json.dump(self.config, f, indent=2)
                print("[CrypticBurp] Profile saved to: %s" % filepath)
            except Exception as e:
                JOptionPane.showMessageDialog(self._main_panel, "Error saving: %s" % str(e))
    
    def _load_profile(self):
        """Load config from JSON file"""
        chooser = JFileChooser()
        chooser.setDialogTitle("Load Profile")
        if chooser.showOpenDialog(self._main_panel) == JFileChooser.APPROVE_OPTION:
            filepath = chooser.getSelectedFile().getAbsolutePath()
            
            try:
                with open(filepath, 'r') as f:
                    self.config = json.load(f)
                
                # Update UI
                self._host_field.setText(self.config.get("target_host", ""))
                self._path_field.setText(self.config.get("target_path", ""))
                self._query_check.setSelected(self.config.get("decrypt_query", True))
                self._req_body_check.setSelected(self.config.get("decrypt_request_body", False))
                self._resp_body_check.setSelected(self.config.get("decrypt_response_body", True))
                self._req_body_type.setSelectedItem(self.config.get("request_body_type", "Raw"))
                self._req_body_field.setText(self.config.get("request_body_field", ""))
                self._resp_body_type.setSelectedItem(self.config.get("response_body_type", "Raw"))
                self._resp_body_field.setText(self.config.get("response_body_field", ""))
                self._algo_combo.setSelectedItem(self.config.get("algorithm", "AES/CBC/NoPadding"))
                self._key_field.setText(self.config.get("key", ""))
                self._iv_field.setText(self.config.get("iv", ""))
                self._key_format.setSelectedItem(self.config.get("key_format", "ASCII"))
                self._iv_same_check.setSelected(self.config.get("iv_same_as_key", True))
                self._iv_field.setEnabled(not self.config.get("iv_same_as_key", True))
                self._encoding_combo.setSelectedItem(self.config.get("encoding", "Base64"))
                self._padding_combo.setSelectedItem(self.config.get("padding", "Tab (0x09)"))
                
                self._apply_config()
                print("[CrypticBurp] Profile loaded from: %s" % filepath)
            except Exception as e:
                JOptionPane.showMessageDialog(self._main_panel, "Error loading: %s" % str(e))
    
    # ITab
    def getTabCaption(self):
        return "CrypticBurp"
    
    def getUiComponent(self):
        return self._main_panel
    
    # IMessageEditorTabFactory
    def createNewInstance(self, controller, editable):
        return CryptoProxyTab(self, controller, editable)
    
    # IHttpListener
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Auto-encrypt outgoing requests with marker"""
        if not messageIsRequest:
            return
        
        # Check host filter
        service = messageInfo.getHttpService()
        if service is None:
            return
        
        host = service.getHost()
        if self.config["target_host"] and host != self.config["target_host"]:
            return
        
        request = messageInfo.getRequest()
        analyzed = self._helpers.analyzeRequest(request)
        headers = list(analyzed.getHeaders())
        
        # Check for marker
        has_marker = any(h.startswith(self.MARKER + ":") for h in headers)
        if not has_marker:
            return
        
        print("[CrypticBurp] Encrypting outgoing request...")
        
        try:
            # Remove marker
            headers = [h for h in headers if not h.startswith(self.MARKER + ":")]
            
            first_line = headers[0]
            parts = first_line.split(" ", 2)
            method = parts[0]
            path_query = parts[1]
            http_ver = parts[2] if len(parts) > 2 else "HTTP/1.1"
            
            body = request[analyzed.getBodyOffset():]
            body_str = self._helpers.bytesToString(body)
            new_body = body
            
            # Encrypt query string if enabled
            if self.config["decrypt_query"] and "?" in path_query:
                base_path, plaintext = path_query.split("?", 1)
                encrypted = self.crypto.encrypt(plaintext)
                if encrypted:
                    path_query = "%s?%s" % (base_path, encrypted)
                    print("[CrypticBurp] Query encrypted")
            
            # Encrypt request body if enabled
            if self.config["decrypt_request_body"] and body_str.strip():
                encrypted_body = self._encrypt_body(body_str, 
                    self.config["request_body_type"], 
                    self.config["request_body_field"])
                if encrypted_body:
                    new_body = encrypted_body.encode('utf-8')
                    print("[CrypticBurp] Request body encrypted")
            
            # Rebuild request
            headers[0] = "%s %s %s" % (method, path_query, http_ver)
            new_request = self._helpers.buildHttpMessage(headers, new_body)
            messageInfo.setRequest(new_request)
            print("[CrypticBurp] Request sent with encryption")
            
        except Exception as e:
            print("[CrypticBurp] Encrypt error: %s" % str(e))
    
    def _encrypt_body(self, body_str, body_type, field_name):
        """Encrypt body based on type"""
        if body_type == "Raw":
            return self.crypto.encrypt(body_str.strip())
        elif body_type == "JSON field" and field_name:
            try:
                obj = json.loads(body_str)
                if field_name in obj:
                    obj[field_name] = self.crypto.encrypt(str(obj[field_name]))
                    return json.dumps(obj)
            except:
                pass
        elif body_type == "Form field" and field_name:
            # Handle form data
            params = body_str.split("&")
            for i, param in enumerate(params):
                if "=" in param:
                    key, val = param.split("=", 1)
                    if key == field_name:
                        encrypted = self.crypto.encrypt(val)
                        if encrypted:
                            params[i] = "%s=%s" % (key, encrypted)
            return "&".join(params)
        return None

class CryptoProxyTab(IMessageEditorTab):
    """Decrypted tab: plain JTextArea view of the decrypted content.
    For requests, edits to either the query-string section or the
    request-body section are re-encrypted on send via processHttpMessage()
    (the MARKER header triggers it)."""

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._controller = controller

        self._txtInput = JTextArea()
        self._txtInput.setFont(Font("Consolas", Font.PLAIN, 13))
        self._txtInput.setLineWrap(True)
        self._txtInput.setWrapStyleWord(True)
        self._scrollPane = JScrollPane(self._txtInput)

        self._currentMessage = None
        self._isRequest = False
        self._originalDecrypted = ""
        self._originalBody = ""
        self._basePath = ""

    def getTabCaption(self):
        return "Decrypted"

    def getUiComponent(self):
        return self._scrollPane

    def isEnabled(self, content, isRequest):
        """Show tab when there's encrypted content matching the configured host."""
        if content is None:
            return False

        if self._extender.config["target_host"]:
            service = self._controller.getHttpService() if self._controller else None
            if service and service.getHost() != self._extender.config["target_host"]:
                return False

        try:
            if isRequest:
                if self._extender.config["decrypt_query"]:
                    analyzed = self._extender._helpers.analyzeRequest(content)
                    headers = analyzed.getHeaders()
                    if headers:
                        first = headers[0]
                        if "?" in first:
                            query = first.split("?", 1)[1].split(" ")[0]
                            if len(query) > 30:
                                return True

                if self._extender.config["decrypt_request_body"]:
                    analyzed = self._extender._helpers.analyzeRequest(content)
                    body = content[analyzed.getBodyOffset():]
                    if len(body) > 20:
                        return True
            else:
                if self._extender.config["decrypt_response_body"]:
                    analyzed = self._extender._helpers.analyzeResponse(content)
                    body = content[analyzed.getBodyOffset():]
                    body_str = self._extender._helpers.bytesToString(body).strip()
                    if len(body_str) > 20:
                        return True
        except:
            pass
        return False

    def setMessage(self, content, isRequest):
        self._currentMessage = content
        self._isRequest = isRequest
        self._originalDecrypted = ""
        self._originalBody = ""
        self._basePath = ""

        if content is None:
            self._txtInput.setText("")
            return

        output_parts = []

        try:
            if isRequest:
                analyzed = self._extender._helpers.analyzeRequest(content)
                headers = list(analyzed.getHeaders())
                first = headers[0]

                if self._extender.config["decrypt_query"] and "?" in first:
                    before_q, after_q = first.split("?", 1)
                    self._basePath = before_q
                    if " HTTP" in after_q:
                        query = after_q.split(" HTTP")[0]
                    else:
                        query = after_q

                    decrypted = self._extender.crypto.decrypt(query)
                    if decrypted and ("=" in decrypted or "&" in decrypted):
                        output_parts.append("=--- QUERY PARAMS ---=\n%s" % decrypted)
                        self._originalDecrypted = decrypted
                    else:
                        output_parts.append("=--- QUERY PARAMS ---=\n%s" % query)
                        self._originalDecrypted = query
                else:
                    self._basePath = ""

                body = content[analyzed.getBodyOffset():]
                body_str = self._extender._helpers.bytesToString(body).strip()

                if self._extender.config["decrypt_request_body"] and body_str:
                    decrypted_body = self._decrypt_body(body_str,
                        self._extender.config["request_body_type"],
                        self._extender.config["request_body_field"])
                    if decrypted_body:
                        output_parts.append("\n=--- REQUEST BODY ---=\n%s" % decrypted_body)
                        self._originalBody = decrypted_body
                    else:
                        output_parts.append("\n=--- REQUEST BODY (raw) ---=\n%s" % body_str)
                        self._originalBody = body_str

                if output_parts:
                    self._txtInput.setText("\n".join(output_parts))
                else:
                    self._txtInput.setText("[No encrypted content found]")
                self._txtInput.setCaretPosition(0)

            else:
                analyzed = self._extender._helpers.analyzeResponse(content)
                body = content[analyzed.getBodyOffset():]
                body_str = self._extender._helpers.bytesToString(body).strip()

                decrypted = self._decrypt_body(body_str,
                    self._extender.config["response_body_type"],
                    self._extender.config["response_body_field"])

                if decrypted:
                    try:
                        obj = json.loads(decrypted)
                        self._txtInput.setText(json.dumps(obj, indent=2, ensure_ascii=False))
                    except:
                        self._txtInput.setText(decrypted)
                    self._originalDecrypted = decrypted
                else:
                    self._txtInput.setText("[Decryption failed]")
                self._txtInput.setCaretPosition(0)

        except Exception as e:
            self._txtInput.setText("[Error: %s]" % str(e))

    def _decrypt_body(self, body_str, body_type, field_name):
        if body_type == "Raw":
            return self._extender.crypto.decrypt(body_str)
        elif body_type == "JSON field" and field_name:
            try:
                obj = json.loads(body_str)
                if field_name in obj:
                    decrypted = self._extender.crypto.decrypt(str(obj[field_name]))
                    if decrypted is None:
                        return None
                    obj[field_name] = decrypted
                    return json.dumps(obj, indent=2)
            except:
                pass
        elif body_type == "Form field" and field_name:
            params = body_str.split("&")
            hit = False
            for i, param in enumerate(params):
                if "=" in param:
                    key, val = param.split("=", 1)
                    if key == field_name:
                        decrypted = self._extender.crypto.decrypt(val)
                        if decrypted:
                            params[i] = "%s=%s" % (key, decrypted)
                            hit = True
            if hit:
                return "&".join(params)
            return None
        return self._extender.crypto.decrypt(body_str)

    def _parse_editor_text(self, text):
        """Split the editor text into (query, body) based on the section
        markers. Either side can be None if that marker isn't present."""
        query_marker = "=--- QUERY PARAMS ---="
        body_markers = ("=--- REQUEST BODY ---=", "=--- REQUEST BODY (raw) ---=")

        # Find the first body marker, if any
        body_idx = -1
        body_marker_used = None
        for m in body_markers:
            idx = text.find(m)
            if idx >= 0 and (body_idx == -1 or idx < body_idx):
                body_idx = idx
                body_marker_used = m

        before_body = text[:body_idx] if body_idx >= 0 else text
        after_body = text[body_idx + len(body_marker_used):] if body_idx >= 0 else None

        query = None
        if query_marker in before_body:
            query = before_body.split(query_marker, 1)[1].strip()

        body = after_body.strip() if after_body is not None else None
        return query, body

    def getMessage(self):
        """Build request with plaintext query/body + marker so
        processHttpMessage re-encrypts before sending."""
        if self._currentMessage is None:
            return None

        if not self._isRequest:
            return self._currentMessage

        try:
            edited_query, edited_body = self._parse_editor_text(self._txtInput.getText())

            # Nothing to round-trip; leave the request alone
            if edited_query is None and edited_body is None:
                return self._currentMessage

            analyzed = self._extender._helpers.analyzeRequest(self._currentMessage)
            headers = list(analyzed.getHeaders())
            headers = [h for h in headers if not h.startswith(self._extender.MARKER + ":")]

            # Rebuild request line only if we have an edited query + a basePath
            if edited_query is not None and self._basePath:
                first = headers[0]
                http_ver = "HTTP/1.1"
                if " HTTP/" in first:
                    http_ver = "HTTP/" + first.split(" HTTP/")[1]
                headers[0] = "%s?%s %s" % (self._basePath, edited_query, http_ver)

            # Use edited body if present, else keep original
            if edited_body is not None:
                body = edited_body.encode('utf-8')
            else:
                body = self._currentMessage[analyzed.getBodyOffset():]

            headers.append("%s: true" % self._extender.MARKER)
            return self._extender._helpers.buildHttpMessage(headers, body)

        except Exception as e:
            print("[CryptoProxyTab] getMessage error: %s" % str(e))
            return self._currentMessage

    def isModified(self):
        if not self._isRequest:
            return self._txtInput.getText() != self._originalDecrypted

        current_query, current_body = self._parse_editor_text(self._txtInput.getText())
        query_modified = current_query is not None and current_query != self._originalDecrypted
        body_modified = current_body is not None and current_body != self._originalBody
        return query_modified or body_modified

    def getSelectedData(self):
        return self._txtInput.getSelectedText()
