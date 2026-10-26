<?php
// Only used in the disposable Docker demo. No public site is contacted.
define('WP_INSTALLING', true);
require '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
if (is_blog_installed()) {
    fwrite(STDERR, "Demo must start with empty volumes. Run the demo cleanup first.\n");
    exit(1);
}
$result = wp_install('Tokening disposable demo', 'operator', 'operator@example.test', true, '', bin2hex(random_bytes(24)));
if (is_wp_error($result)) { throw new RuntimeException('WordPress installation failed.'); }
$activated = activate_plugin('mcp-adapter/mcp-adapter.php');
if (is_wp_error($activated)) { throw new RuntimeException($activated->get_error_message()); }
foreach (get_posts(array('post_type' => 'any', 'post_status' => 'any', 'numberposts' => -1)) as $post) {
    wp_delete_post($post->ID, true);
}
for ($id = 1; $id <= 3; $id++) {
    $created = wp_insert_post(array('import_id' => $id, 'post_type' => 'post', 'post_status' => 'publish', 'post_title' => "Seed post $id", 'post_content' => "Original body for post $id.", 'post_author' => $result['user_id']), true);
    if (is_wp_error($created) || $created !== $id) { throw new RuntimeException('Deterministic post IDs were not created.'); }
}
$password = WP_Application_Passwords::create_new_application_password($result['user_id'], array('name' => 'Tokening Docker demo'));
if (is_wp_error($password)) { throw new RuntimeException('Application password creation failed.'); }
umask(0077);
file_put_contents('/secrets/wordpress.json', wp_json_encode(array('username' => 'operator', 'password' => $password[0])));
update_option('tokening_demo_writes', 0);
update_option('tokening_demo_deletes', 0);
echo "Seeded three disposable WordPress posts and a private application password.\n";
