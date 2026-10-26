<?php
// Read-only snapshot of the seeded posts, taken before the agent runs so the
// replay can show each post's starting title next to the verified final state.
require '/var/www/html/wp-load.php';
$posts = array();
for ($id = 1; $id <= 3; $id++) {
    $post = get_post($id);
    if (!$post) { throw new RuntimeException('A seed post is missing.'); }
    $posts[] = array('id' => $id, 'title' => $post->post_title, 'content' => $post->post_content, 'status' => $post->post_status);
}
echo wp_json_encode($posts) . "\n";
