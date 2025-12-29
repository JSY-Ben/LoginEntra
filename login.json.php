<?php
header('Access-Control-Allow-Headers: Content-Type');
require_once dirname(__FILE__) . '/../../videos/configuration.php';
require_once $global['systemRootPath'] . 'objects/autoload.php';
require_once $global['systemRootPath'] . 'objects/user.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    _session_start();
}

$obj = AVideoPlugin::getDataObjectIfEnabled('LoginEntra');
if (empty($obj)) {
    forbiddenPage('LoginEntra is disabled');
}

$clientId = trim((string)($obj->client_id ?? ''));
$clientSecret = trim((string)($obj->client_secret ?? ''));
$tenantId = trim((string)($obj->tenant_id ?? ''));
$allowedDomains = array_filter(array_map('trim', explode(',', (string)($obj->allowed_domains ?? ''))));

if (empty($clientId) || empty($clientSecret) || empty($tenantId)) {
    forbiddenPage('LoginEntra is not configured (client_id, client_secret, tenant_id)');
}

$redirectUri = $global['webSiteRootURL'] . "plugin/LoginEntra/login.json.php";

function loginentraGetSafeRedirectUrl($url, $webRoot) {
    $url = trim((string)$url);
    if ($url === '') {
        return '';
    }

    // Allow relative URLs that stay within this site.
    if ($url[0] === '/') {
        return $url;
    }

    // Allow absolute URLs only if they match this site's host.
    $target = parse_url($url);
    $root = parse_url($webRoot);
    if (!empty($target['host']) && !empty($root['host']) && strcasecmp($target['host'], $root['host']) === 0) {
        return $url;
    }

    return '';
}

function b64url_decode($data) {
    $data = strtr($data, '-_', '+/');
    $pad = strlen($data) % 4;
    if ($pad) $data .= str_repeat('=', 4 - $pad);
    return base64_decode($data);
}

function loginentraEnsureTable($mysqli) {
    $sql = "CREATE TABLE IF NOT EXISTS loginentra_bindings (
        users_id INT(11) NOT NULL PRIMARY KEY,
        oid VARCHAR(64) NOT NULL,
        tid VARCHAR(64) NOT NULL,
        created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_oid_tid (oid, tid)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    @$mysqli->query($sql);
}

function loginentraEnforceBinding($mysqli, $users_id, $oid, $tid) {
    $users_id = (int)$users_id;
    $oidEsc = $mysqli->real_escape_string($oid);
    $tidEsc = $mysqli->real_escape_string($tid);

    // If this Entra identity is already bound to a different local account, deny.
    $sql = "SELECT users_id FROM loginentra_bindings WHERE oid='{$oidEsc}' AND tid='{$tidEsc}' LIMIT 1";
    $res = $mysqli->query($sql);
    if ($res && ($row = $res->fetch_assoc())) {
        if ((int)$row['users_id'] !== $users_id) {
            forbiddenPage('This Entra account is already linked to a different AVideo user.');
        }
    }

    // If this local account is already bound, enforce match.
    $sql = "SELECT oid, tid FROM loginentra_bindings WHERE users_id={$users_id} LIMIT 1";
    $res = $mysqli->query($sql);
    if ($res && ($row = $res->fetch_assoc())) {
        if ($row['oid'] !== $oid || $row['tid'] !== $tid) {
            forbiddenPage('This AVideo user is already linked to a different Entra identity.');
        }
        return;
    }

    // Create binding
    $sql = "INSERT INTO loginentra_bindings (users_id, oid, tid) VALUES ({$users_id}, '{$oidEsc}', '{$tidEsc}')";
    if (!$mysqli->query($sql)) {
        forbiddenPage('Could not create Entra binding (already linked).');
    }
}

// Step 1: start auth flow
if (empty($_GET['code'])) {
    $csrf = bin2hex(random_bytes(16));
    $returnTo = loginentraGetSafeRedirectUrl($_GET['redirectUrl'] ?? '', $global['webSiteRootURL']);
    $_SESSION['loginentra_state_csrf'] = $csrf;
    if (!empty($returnTo)) {
        $_SESSION['loginentra_return_to'] = $returnTo;
    }

    $statePayload = [
        'csrf' => $csrf,
    ];
    if (!empty($returnTo)) {
        $statePayload['returnTo'] = $returnTo;
    }
    $state = base64_encode(json_encode($statePayload));

    // IMPORTANT: do NOT request "groups" as a scope (it is not a valid v2 scope).
    // If you later want group info, configure a groups *claim* in Token configuration instead.
    $authorizeUrl = "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/authorize";
    $params = [
        'client_id' => $clientId,
        'response_type' => 'code',
        'redirect_uri' => $redirectUri,
        'response_mode' => 'query',
        'scope' => 'openid profile email',
        'state' => $state,
    ];
    header("Location: {$authorizeUrl}?" . http_build_query($params));
    exit;
}

// Step 2: validate state
if (empty($_GET['state'])) {
    forbiddenPage('Invalid state');
}
$stateRaw = base64_decode($_GET['state'], true);
$stateData = json_decode($stateRaw ?? '', true);
if (empty($stateData['csrf']) || !hash_equals($_SESSION['loginentra_state_csrf'] ?? '', $stateData['csrf'])) {
    forbiddenPage('Invalid state');
}

// Step 3: exchange code for token
$tokenUrl = "https://login.microsoftonline.com/{$tenantId}/oauth2/v2.0/token";
$post = [
    'client_id' => $clientId,
    'client_secret' => $clientSecret,
    'grant_type' => 'authorization_code',
    'code' => $_GET['code'],
    'redirect_uri' => $redirectUri,
];

$ch = curl_init($tokenUrl);
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => http_build_query($post),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 15,
]);
$res = curl_exec($ch);
$curlErr = curl_error($ch);
curl_close($ch);

if ($res === false) {
    forbiddenPage('Token request failed: ' . $curlErr);
}
$token = json_decode($res);
if (empty($token->id_token)) {
    forbiddenPage('No id_token returned from Entra');
}

// Step 4: parse JWT claims
$parts = explode('.', $token->id_token);
if (count($parts) < 2) {
    forbiddenPage('Invalid id_token format');
}
$claimsJson = b64url_decode($parts[1]);
$claims = json_decode($claimsJson);

$email = $claims->preferred_username ?? $claims->email ?? '';
$name = $claims->name ?? $email;
$oid = $claims->oid ?? '';
$tid = $claims->tid ?? '';

if (empty($email) || empty($oid) || empty($tid)) {
    forbiddenPage('Missing required claims (email/oid/tid)');
}

// Enforce single-tenant (tid must match configured tenant_id)
if (strcasecmp($tid, $tenantId) !== 0) {
    forbiddenPage('Invalid tenant');
}

// Optional: restrict by email domain
if (!empty($allowedDomains)) {
    $domain = strtolower(substr(strrchr($email, "@") ?: "", 1));
    $allowedLower = array_map('strtolower', $allowedDomains);
    if (empty($domain) || !in_array($domain, $allowedLower, true)) {
        forbiddenPage('Email domain not allowed');
    }
}

// Step 5: login / auto-provision
$user = $email;
$pass = rand();
User::createUserIfNotExists($user, $pass, $name, $email, "", false, true);

$userObj = new User(0, $user, $pass);
$userObj->login(true);

$users_id = User::getId();
if (empty($users_id)) {
    forbiddenPage('Could not login user');
}

// Step 6: OID+TID binding (plugin-local table; no core edits required)
$mysqli = $global['mysqli'] ?? null;
if (!empty($mysqli)) {
    loginentraEnsureTable($mysqli);
    loginentraEnforceBinding($mysqli, $users_id, $oid, $tid);
}

$returnTo = loginentraGetSafeRedirectUrl($stateData['returnTo'] ?? ($_SESSION['loginentra_return_to'] ?? ''), $global['webSiteRootURL']);
if (empty($returnTo)) {
    $returnTo = $global['webSiteRootURL'];
}
header("Location: {$returnTo}");
exit;
?>
