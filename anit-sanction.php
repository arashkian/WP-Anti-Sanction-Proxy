<?php
/*
Plugin Name: WP Anti-Sanction Proxy
Plugin URI: https://7ho.st
Description: افزونه رفع تحریم وردپرس — عبور درخواست‌های وردپرس و المنتور از پراکسی برای رفع محدودیت‌های تحریم.
Version: 1.4
Author: Arash Kian
Author URI: https://github.com/arashkian
License: GPLv2 or later
Text Domain: wp-anti-sanction-proxy
*/

$custom_proxy_hosts = [
    'elementor.com',
    'api.wordpress.org',
    'downloads.wordpress.org',
    'my.elementor.com',
    'library.elementor.com',
    'plugin-downloads.elementor.com',
    'elementor.api.kustomerapp.com',
];

define('WPASP_SECRET_KEY', 'AntiSanction2025!@#');

function wpasp_encrypt($data) {
    if (!$data) return '';
    $ivlen = openssl_cipher_iv_length('AES-256-CBC');
    $iv = openssl_random_pseudo_bytes($ivlen);
    $cipher = openssl_encrypt($data, 'AES-256-CBC', WPASP_SECRET_KEY, 0, $iv);
    return base64_encode($iv . $cipher);
}

function wpasp_decrypt($data) {
    if (!$data) return '';
    $data = base64_decode($data);
    $ivlen = openssl_cipher_iv_length('AES-256-CBC');
    $iv = substr($data, 0, $ivlen);
    $cipher = substr($data, $ivlen);
    return openssl_decrypt($cipher, 'AES-256-CBC', WPASP_SECRET_KEY, 0, $iv);
}

add_action('admin_menu', function() {
    add_options_page(
        'WP Anti-Sanction Proxy',
        'Anti-Sanction Proxy',
        'manage_options',
        'wp-anti-sanction-proxy',
        'wpasp_settings_page'
    );
});

function wpasp_settings_page() {
    $host = wpasp_decrypt(get_option('wpasp_host'));
    $port = wpasp_decrypt(get_option('wpasp_port'));
    $user = wpasp_decrypt(get_option('wpasp_user'));
    $pass = wpasp_decrypt(get_option('wpasp_pass'));

    if (isset($_POST['reset_proxy_settings'])) {
        check_admin_referer('wpasp_reset');
        delete_option('wpasp_host');
        delete_option('wpasp_port');
        delete_option('wpasp_user');
        delete_option('wpasp_pass');
        echo '<div class="updated"><p>⚙️ تنظیمات حذف شدند. اکنون می‌توانید دوباره مقداردهی کنید.</p></div>';
        $host = $port = $user = $pass = '';
    }

    if (isset($_POST['save_proxy_settings'])) {
        check_admin_referer('wpasp_save');

        $host = sanitize_text_field($_POST['proxy_host']);
        $port = sanitize_text_field($_POST['proxy_port']);
        $user = sanitize_text_field($_POST['proxy_username']);
        $pass = sanitize_text_field($_POST['proxy_password']);

        update_option('wpasp_host', wpasp_encrypt($host));
        update_option('wpasp_port', wpasp_encrypt($port));
        update_option('wpasp_user', wpasp_encrypt($user));
        update_option('wpasp_pass', wpasp_encrypt($pass));

        echo '<div class="updated"><p>✅ تنظیمات با موفقیت ذخیره شد.</p></div>';
    }

    $configured = ($host && $port);

    echo '<div class="wrap"><h1>🌐 WP Anti-Sanction Proxy</h1>';

    if ($configured && !isset($_POST['reset_proxy_settings'])) {
        echo '<p>پراکسی در حال حاضر فعال است و تنظیمات ذخیره شده‌اند ✅</p>';
        echo '<form method="post">';
        wp_nonce_field('wpasp_reset');
        echo '<button type="submit" name="reset_proxy_settings" class="button">🧹 حذف تنظیمات و ورود مجدد</button>';
        echo '</form>';
    } else {
        ?>
        <p>این افزونه ترافیک وردپرس (مانند Elementor و WordPress.org) را از طریق پراکسی عبور می‌دهد تا محدودیت‌های تحریم رفع شوند.</p>
        <hr>
        <form method="post">
            <?php wp_nonce_field('wpasp_save'); ?>
            <table class="form-table">
                <tr><th>Proxy Host</th><td><input type="text" name="proxy_host" value="" class="regular-text"></td></tr>
                <tr><th>Proxy Port</th><td><input type="text" name="proxy_port" value="" class="regular-text"></td></tr>
                <tr><th>Proxy Username</th><td><input type="text" name="proxy_username" value="" class="regular-text"></td></tr>
                <tr><th>Proxy Password</th><td><input type="password" name="proxy_password" value="" class="regular-text"></td></tr>
            </table>
            <p><button type="submit" name="save_proxy_settings" class="button button-primary">💾 ذخیره تنظیمات</button></p>
        </form>
        <?php
    }

    echo '</div>';
}

add_filter('http_request_args', function ($args, $url) use ($custom_proxy_hosts) {
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host) return $args;

    $proxy_host = wpasp_decrypt(get_option('wpasp_host'));
    $proxy_port = wpasp_decrypt(get_option('wpasp_port'));
    $proxy_user = wpasp_decrypt(get_option('wpasp_user'));
    $proxy_pass = wpasp_decrypt(get_option('wpasp_pass'));

    if (!$proxy_host || !$proxy_port) return $args;

    foreach ($custom_proxy_hosts as $h) {
        if (stripos($host, $h) !== false) {
            $args['proxy'] = $proxy_host . ':' . $proxy_port;
            if ($proxy_user && $proxy_pass) {
                $args['headers']['Proxy-Authorization'] =
                    'Basic ' . base64_encode($proxy_user . ':' . $proxy_pass);
            }
            break;
        }
    }
    return $args;
}, 10, 2);

add_action('http_api_curl', function ($handle, $r, $url) use ($custom_proxy_hosts) {
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host) return;

    $proxy_host = wpasp_decrypt(get_option('wpasp_host'));
    $proxy_port = wpasp_decrypt(get_option('wpasp_port'));
    $proxy_user = wpasp_decrypt(get_option('wpasp_user'));
    $proxy_pass = wpasp_decrypt(get_option('wpasp_pass'));

    if (!$proxy_host || !$proxy_port) return;

    foreach ($custom_proxy_hosts as $h) {
        if (stripos($host, $h) !== false) {
            curl_setopt($handle, CURLOPT_PROXY, $proxy_host . ':' . $proxy_port);
            if ($proxy_user && $proxy_pass) {
                curl_setopt($handle, CURLOPT_PROXYUSERPWD, $proxy_user . ':' . $proxy_pass);
            }
            curl_setopt($handle, CURLOPT_HTTPPROXYTUNNEL, true);
            break;
        }
    }
}, 10, 3);
