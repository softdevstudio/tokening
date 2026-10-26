<?php
require '/var/www/html/wp-load.php';
$posts = array();
for ($id = 1; $id <= 3; $id++) {
    $post = get_post($id);
    if (!$post) { throw new RuntimeException('A seed post was deleted.'); }
    $posts[] = array('id' => $id, 'title' => $post->post_title, 'content' => $post->post_content, 'status' => $post->post_status);
}
if ($posts[0]['title'] !== 'Seed post 1' || $posts[2]['title'] !== 'Seed post 3' || $posts[1]['title'] !== 'Parallel edit' || $posts[1]['content'] !== 'Original body for post 2.' || $posts[1]['status'] !== 'publish' || (int) get_option('tokening_demo_writes') !== 2 || (int) get_option('tokening_demo_deletes') !== 0) {
    throw new RuntimeException('Unexpected WordPress state after the permission demo.');
}
echo wp_json_encode(array('posts' => $posts, 'writes' => (int) get_option('tokening_demo_writes'), 'deletes' => (int) get_option('tokening_demo_deletes'), 'wordpress_version' => $GLOBALS['wp_version'], 'adapter_version' => get_file_data(WP_PLUGIN_DIR . '/mcp-adapter/mcp-adapter.php', array('Version' => 'Version'))['Version'])) . "\n";
