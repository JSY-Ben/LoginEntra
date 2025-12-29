# LoginEntra - Microsoft Entra Authentication Plugin for AVideo Platform

This plugin allows you to use Microsoft Entra as an authentication source for users to login to the [AVideo Open-Source Video Platform](https://github.com/WWBN/AVideo)

# Setup Microsoft Entra to work with this plugin

To allow this plugin to work, you will have to create an 'App Registration' on Microsoft Entra, with the following API Permissions:

```
email
openid
profile
User.Read
```

Remembering to 'Grant Admin Consent' for your Tenant so users aren't asked for permission when they first login to use the app. 

[Official Instructions from Microsoft on how to create an app Registration on Entra are available here](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)

# Configuring Plugin Parameters

When the plugin is installed, click 'Edit Parameters' and fill in the following config options:

client_id: Your Application (client) ID in Microsoft Entra App Registrations

client_secret: Your API Client Secret from Microsoft Entra

tenant_id: Your Microsoft Entra Tenant ID

allowed_domains: Please set which email domains you wish to be allows to login to your AVideo installation. You can comma separate entries if you'd like to add more than one (e.g. avideo.com,avideo.co.uk)

If you wish to make this the only available login option, you can enable the 'disableNativeSignIn' option in the 'CustomizeUser' plugin of AVideo,. however make sure that this plugin is working and one of your Entra users is an Admin before you do this, otherwise you will not be able to login to your installation again without enabling the Native Sign In method manually in the AVideo mySQL database. 

# Creating a 'Sign in with Microsoft' button on the login page.

As I did not want to mess with the code of the main plugin, this plugin uses its own login handler, therefore it won't create a 'Sign in with Microsoft' button on the main login page like the other AVideo created Login plugins do when they're enabled. Please feel free to use the HTML code below to create your own login button, i suggest in the 'messageToAppearBelowLoginBox' setting of the 'CustomizeUser' plugin of AVideo.


```html
<div style="text-align:center;">
  <a id="entra-login-btn"
     href="https://youravideo.com/plugin/LoginEntra/login.json.php"
     style="display:inline-flex;align-items:center;gap:14px;
            padding:16px 22px;border:2px solid #4a4a4a;border-radius:8px;
            background:#1f1f1f;color:#ffffff;text-decoration:none;
            font:18px/1.2 'Segoe UI', Arial, sans-serif;font-weight:600;
            box-shadow:0 6px 16px rgba(0,0,0,0.35), 0 0 10px rgba(0,164,239,0.25);">
    <svg width="24" height="24" viewBox="0 0 18 18" aria-hidden="true">
      <rect x="1" y="1" width="7" height="7" fill="#F25022"></rect>
      <rect x="10" y="1" width="7" height="7" fill="#7FBA00"></rect>
      <rect x="1" y="10" width="7" height="7" fill="#00A4EF"></rect>
      <rect x="10" y="10" width="7" height="7" fill="#FFB900"></rect>
    </svg>
    <span>Sign in with Microsoft</span>
  </a>
</div>
<script>
  (function () {
    var btn = document.getElementById('entra-login-btn');
    if (!btn) return;

    var base = btn.getAttribute('href');
    var url = new URL(window.location.href);
    var redirectUri = url.searchParams.get('redirectUri');

    var target = redirectUri ? redirectUri : url.toString();
    btn.setAttribute('href', base + '?redirectUrl=' + encodeURIComponent(target));
  })();
</script>
```
