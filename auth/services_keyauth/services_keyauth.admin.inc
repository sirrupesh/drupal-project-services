<?php
// $Id$

/**
 * @file
 *  Generate security keys.
 */

function services_keyauth_admin_keys_list() {
  $keys = services_keyauth_get_keys();
  $header = array(t('Key'), t('Title'), t('Domain'), array('data' => t('Operations'), 'colspan' => '2'));
  $rows = array();

  foreach ($keys as $kid => $key) {
    $row = array();

    $row[] = $kid;
    $row[] = $key->title;
    $row[] = $key->domain;

    // Populate the operations field.
    $operations = array();

    // Set the edit column.
    $operations[] = array('data' => l(t('edit'), 'admin/build/services/keys/' . $kid));

    // Set the delete column.
    $operations[] = array('data' => l(t('delete'), 'admin/build/services/keys/' . $kid .'/delete'));

    foreach ($operations as $operation) {
      $row[] = $operation;
    }
    $rows[] = $row;
  }

  if (!count($rows)) {
    $rows[] = array(array('data' => t('No API keys created.'), 'colspan' => '5', 'class' => 'message'));
  }

  return theme('table', array('header' => $header, 'rows' => $rows));
}

function services_keyauth_admin_keys_form() {
  $kid = arg(4);
  $key = db_query("SELECT * FROM {services_keys} WHERE kid = :key", array(':key' => $kid))->fetchObject();

  $key_kid = isset($key->kid) ? $key->kid : '';
  $key_title = isset($key->title) ? $key->title : '';
  $form['kid'] = array(
    '#type'           => 'hidden',
    '#default_value'  => $key_kid,
  );

  $accessible_methods = array();
  if ($key_kid != '') {
    $form['key'] = array(
      '#type'           => 'markup',
      '#title'          => t('Key'),
      '#value'          => '<strong>'. t('API Key') . ':</strong> ' . $key_kid,
    );
    $result = db_query("SELECT method FROM {services_key_permissions} WHERE kid = :key", array(':key' => $kid));
    while ($kid = $result->fetchObject()) {
      $accessible_methods[] = $kid->method;
    }
  }

  $form['title'] = array(
    '#title'          => t('Application title'),
    '#type'           => 'textfield',
    '#default_value'  => $key_title,
    '#description'    => t('The title of the application or website using the service.'),
  );
  $form['domain'] = array(
    '#title'          => t('Allowed domain'),
    '#type'           => 'textfield',
    '#default_value'  => isset($key->domain) ? $key->domain : '',
    '#description'    => t('External domain allowed to use this key.'),
    '#required'       => TRUE,
  );
  
  $methods = services_get_all();

  $form_methods = array();

  foreach ($methods as $method) {
    $form_methods[$method['#method']] = $method['#method'];
  }

  $form['method_access'] = array(
    '#type' => 'checkboxes',
    '#title' => t('Method access'),
    '#options' => $form_methods,
    '#default_value' => $accessible_methods,
    '#description' => t('Define which methods are accessible.'),
  );

  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => $key_title != '' ? t('Save key') : t('Create key'),
  );

  return $form;
}

function services_keyauth_admin_keys_form_submit($form, &$form_state) {
  services_keyauth_admin_keys_save($form_state['values']);

  $form_state['redirect']  =  'admin/build/services/keys';
}

function services_keyauth_admin_keys_save(&$key) {
  $key['kid'] = !empty($key['kid']) ? $key['kid'] : md5(uniqid(mt_rand(), TRUE));

  $is_existing = (bool) db_query_range("SELECT 1 FROM {services_keys} WHERE kid = :kid", 0, 1, array(':kid' => $key['kid']))->fetchField();
  if ($is_existing) {
    db_update('services_keys')
      ->fields(array(
        'title' => $key['title'],
        'domain' => $key['domain'],
      ))
      ->condition('kid', $key['kid'], '=')
      ->execute();
    db_delete('services_key_permissions')
      ->condition('kid', $key['kid'])
      ->execute();
    $return = SAVED_UPDATED;
  }
  else {
    db_insert('services_keys')
        ->fields(array('kid', 'title', 'domain'))
        ->values(array(
          'kid' => $key['kid'],
          'title' => $key['title'],
          'domain' => $key['domain'],
        ))
        ->execute();
    $return = SAVED_NEW;
  }
  foreach ($key['method_access'] as $method => $value) {
    if ($value) {
      db_insert('services_key_permissions')
        ->fields(array('kid', 'method'))
        ->values(array(
          'kid' => $key['kid'],
          'method' => $value,
        ))
        ->execute();
    }
  }
  return $return; 
}

function services_keyauth_admin_keys_delete($kid) {
  db_delete('services_keys')
      ->condition('kid', $kid)
      ->execute();
}

function services_keyauth_admin_keys_delete_confirm() {
  $kid = arg(4);
  
  $key = db_query("SELECT * FROM {services_keys} WHERE kid = :kid", array(':kid' => $kid))->fetchObject();

  $form['kid'] = array('#type' => 'value', '#value' => $key->kid);

  $message = t('Are you sure you want to delete the key %key?', array('%key' => $key->kid));
  $caption = '';

  $caption .= '<p>'. t('This action cannot be undone.') .'</p>';

  return confirm_form($form, $message, 'admin/build/services/keys', $caption, t('Delete'));
}

function services_keyauth_admin_keys_delete_confirm_submit($form, &$form_state) {
  services_keyauth_admin_keys_delete($form_state['values']['kid']);

  $t_args = array('%key' => $form_state['values']['kid']);
  drupal_set_message(t('The key %key has been deleted.', $t_args));
  watchdog('menu', 'Deleted key %key.', $t_args, WATCHDOG_NOTICE);

  $form_state['redirect'] = 'admin/build/services/keys';
}
