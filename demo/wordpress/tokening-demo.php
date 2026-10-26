<?php
/**
 * Plugin Name: Tokening Docker demo abilities
 * Description: Broad post tools for the disposable Tokening permission demonstration.
 * License: Apache-2.0
 */
defined('ABSPATH') || exit;
add_filter('mcp_adapter_create_default_server', '__return_false');
add_filter('wp_is_application_passwords_available', '__return_true');
add_filter('mcp_adapter_tool_name', function ($name, $ability) {
    $names = array('tokening/update-post' => 'wp_update_post', 'tokening/get-post' => 'wp_get_post', 'tokening/delete-post' => 'wp_delete_post');
    return $names[$ability->get_name()] ?? $name;
}, 10, 2);
add_action('wp_abilities_api_init', function () {
    $id = array('type' => 'integer', 'minimum' => 1);
    $common = array('category' => 'site', 'permission_callback' => function () { return current_user_can('edit_posts'); }, 'meta' => array('mcp' => array('public' => true, 'type' => 'tool')));
    wp_register_ability('tokening/update-post', array_merge($common, array(
        'label' => 'Update post', 'description' => 'Update title, content or status on any post the operator can edit.',
        'input_schema' => array('type' => 'object', 'properties' => array('id' => $id, 'title' => array('type' => 'string'), 'content' => array('type' => 'string'), 'status' => array('type' => 'string')), 'required' => array('id'), 'additionalProperties' => false),
        'execute_callback' => function ($args) {
            $post = array('ID' => $args['id']);
            foreach (array('title' => 'post_title', 'content' => 'post_content', 'status' => 'post_status') as $key => $field) { if (isset($args[$key])) { $post[$field] = $args[$key]; } }
            $result = wp_update_post($post, true);
            if (is_wp_error($result)) { return $result; }
            update_option('tokening_demo_writes', (int) get_option('tokening_demo_writes', 0) + 1);
            return array('id' => $result, 'title' => get_the_title($result), 'content' => get_post_field('post_content', $result));
        }
    )));
    wp_register_ability('tokening/get-post', array_merge($common, array(
        'label' => 'Get post', 'description' => 'Read a post.',
        'input_schema' => array('type' => 'object', 'properties' => array('id' => $id), 'required' => array('id'), 'additionalProperties' => false),
        'execute_callback' => function ($args) { $post = get_post($args['id']); return $post ? array('id' => $post->ID, 'title' => $post->post_title, 'content' => $post->post_content) : new WP_Error('missing_post', 'Post does not exist.'); }
    )));
    wp_register_ability('tokening/delete-post', array_merge($common, array(
        'label' => 'Delete post', 'description' => 'Delete any post the operator can delete.',
        'input_schema' => array('type' => 'object', 'properties' => array('id' => $id), 'required' => array('id'), 'additionalProperties' => false),
        'execute_callback' => function ($args) { $result = wp_delete_post($args['id'], true); if (!$result) { return new WP_Error('delete_failed', 'Post could not be deleted.'); } update_option('tokening_demo_deletes', (int) get_option('tokening_demo_deletes', 0) + 1); return array('deleted' => $args['id']); }
    )));
});
add_action('mcp_adapter_init', function ($adapter) {
    $adapter->create_server('tokening-demo', 'tokening-demo', 'mcp', 'Tokening demo', 'Disposable WordPress post tools', '0.1.0',
        array(\WP\MCP\Transport\HttpTransport::class), \WP\MCP\Infrastructure\ErrorHandling\ErrorLogMcpErrorHandler::class,
        \WP\MCP\Infrastructure\Observability\NullMcpObservabilityHandler::class,
        array('tokening/update-post', 'tokening/get-post', 'tokening/delete-post'), array(), array(),
        function () { return current_user_can('edit_posts'); });
});
