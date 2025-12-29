<?php
require_once $global['systemRootPath'] . 'plugin/Plugin.abstract.php';

class LoginEntra extends PluginAbstract {

    public function getTags() {
        return [PluginTags::$FREE, PluginTags::$LOGIN];
    }

    public function getDescription() {
        global $global;
        $cbWeb = "{$global['webSiteRootURL']}plugin/LoginEntra/login.json.php";
        $cbMobile = "{$global['webSiteRootURL']}plugin/LoginEntra/oauth2.php";
        $str = "Login with Microsoft Entra ID (single-tenant) OAuth Integration";
        $str .= "<br>Valid OAuth redirect URI (web): <strong>{$cbWeb}</strong>";
        $str .= "<br>Valid OAuth redirect URI (mobile): <strong>{$cbMobile}</strong>";
        return $str;
    }

    public function getName() {
        return "LoginEntra";
    }

    public function getUUID() {
        return "8f3c9d6a-1c44-4e77-bf0e-4d0b2b71c4d1";
    }

    public function getPluginVersion() {
        return "1.1";
    }

    public function getEmptyDataObject() {
        $obj = new stdClass();
        $obj->client_id = "";
        $obj->client_secret = "";
        $obj->tenant_id = "";
        $obj->allowed_domains = "";
        return $obj;
    }

    public function getLogin() {
        return null;
    }
}
?>
