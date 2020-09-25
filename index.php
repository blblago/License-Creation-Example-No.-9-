<?php

final class ModelExtensionModuleUniqMegamenu
{
	
	private static $datakey = "93e2ce885e36fa413bc83dc5b9f561b3fd3246df";
	
	public function activation($key)
    {
        if ($this->getKey($key)) {
            $this->addKey($key);
        }
    }
    public function getPermission()
    {
        $this->getLicenseStatus();
        return self::$permission;
    }
	    public function getDomain()
    {
        $srv = str_replace("www.", "", $_SERVER["SERVER_NAME"]);
        return $srv;
    }
    private function getLicenseStatus()
    {
        $license_info = $this->getLicense(self::$code);
        $this->load->language("extension/module/uniq_megamenu");
        unset($this->session->data["error"]);
        if ($license_info) {
            if (isset($license_info["module_data"]) && 63 < strlen($license_info["module_data"]) && base64_encode(base64_decode($license_info["module_data"], true)) === $license_info["module_data"]) {
                if (self::getDate($license_info["module_data"])) {
                    if ($license_info["module_info"]) {
                        if (!$this->getKey($license_info["module_info"])) {
                            $this->session->data["error"] = "Activation key error!";
                        }
                    } else {
                        $this->session->data["error"] = "Error Module Data!";
                    }
                } else {
                    $this->session->data["error"] = "Activation Expired";
                }
            } else {
                $this->session->data["error"] = "Error Module Data!";
            }
        } else {
            $this->session->data["error"] = $this->language->get("activation_need");
        }
    }
    private function getLicense($code)
    {
        $query = $this->db->query("SELECT * FROM `" . DB_PREFIX . "uniq` WHERE `module_code` = '" . $this->db->escape($code) . "'");
        if ($query->num_rows) {
            return $query->row;
        }
        return array();
    }
    private static function addDate()
    {
        $end_date_temp = mktime(0, 0, 0, date("m"), date("d") + 1, date("Y") + 1);
        $end_date = date("Y-m-d", $end_date_temp);
        $key = self::$datakey;
        $ocil = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        $orpb = openssl_random_pseudo_bytes($ocil);
        $os_enc = openssl_encrypt($end_date, $cipher, $key, $options = OPENSSL_RAW_DATA, $orpb);
        $hhmac = hash_hmac("sha256", $os_enc, $key, $as_binary = true);
        $expiration = base64_encode($orpb . $hhmac . $os_enc);
        return $expiration;
    }
    private static function getDate($date)
    {
        $today = date("Y-m-d");
        $key = self::$datakey;
        $bdd = base64_decode($date);
        $ocil = openssl_cipher_iv_length($cipher = "AES-128-CBC");
        $orpb = substr($bdd, 0, $ocil);
        $hhmac = substr($bdd, $ocil, $sha2len = 32);
        $os_enc = substr($bdd, $ocil + $sha2len);
        $orig_date = openssl_decrypt($os_enc, $cipher, $key, $options = OPENSSL_RAW_DATA, $orpb);
        $calcmac = hash_hmac("sha256", $os_enc, $key, $as_binary = true);
        if (hash_equals($hhmac, $calcmac)) {
            $expiration = $orig_date;
        } else {
            $expiration = "00-00-00";
        }
        if ($today < $expiration) {
            return true;
        }
        return false;
    }
    private static function getHost()
    {
        $host1 = $host2 = "localhost";
        $srv = str_replace("www.", "", $_SERVER["SERVER_NAME"]);
        $srv_array = explode(".", $srv);
        if (count($srv_array) < 3) {
            $host1 = $srv;
        }
        if (count($srv_array) == 3) {
            $host1 = $srv;
            $host2 = implode(".", array_slice($srv_array, 1));
        }
        if (count($srv_array) == 4) {
            $host1 = implode(".", array_slice($srv_array, 1));
            $host2 = implode(".", array_slice($srv_array, 2));
        }
        if (count($srv_array) == 5) {
            $host1 = implode(".", array_slice($srv_array, 2));
            $host2 = implode(".", array_slice($srv_array, 3));
        }
        $output1 = sha1($host1 . sha1("N7mBJji29S1x" . sha1($host1)));
        $output2 = sha1($host2 . sha1("N7mBJji29S1x" . sha1($host2)));
        return array($output1, $output2);
    }
    private function addKey($key)
    {
        if (self::$permission) {
            $this->addLicense(self::$code, $key, self::addDate());
        }
    }
    private function addLicense($code, $key, $date)
    {
        $this->db->query("DELETE FROM `" . DB_PREFIX . "uniq` WHERE `module_code` = '" . $this->db->escape($code) . "'");
        $this->db->query("INSERT INTO `" . DB_PREFIX . "uniq` SET `module_code` = '" . $this->db->escape($code) . "', `module_info` = '" . $this->db->escape($key) . "', `module_data` = '" . $this->db->escape($date) . "'");
    }
    private function getKey($key)
    {
        if (password_verify(self::getHost()[0], $key) || password_verify(self::getHost()[1], $key)) {
            self::$permission = true;
            unset($this->session->data["error"]);
            unset($this->session->data["info"]);
        }
        return self::$permission;
    }
	
	if (self::$permission) {
		
	}
}
