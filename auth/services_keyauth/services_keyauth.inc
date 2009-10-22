<?php
// $Id$

/**
 * @file
 *  The implementation of the key authentication scheme
 */

function _services_keyauth_security_settings() {
  $form['security']['options']['services_use_key'] = array(
    '#type'           => 'checkbox',
    '#title'          => t('Use keys'),
    '#default_value'  => variable_get('services_use_key', TRUE),
    '#description'    => t('When enabled all method calls need to provide a validation token to autheciate themselves with the server.'),
  );
  $form['security']['options']['services_key_expiry'] = array(
    '#type'           => 'textfield',
    '#prefix'         => "<div id='services-key-expiry'>",
    '#suffix'         => "</div>",
    '#title'          => t('Token expiry time'),
    '#default_value'  => variable_get('services_key_expiry', 30),
    '#description'    => t('The time frame for which the token will be valid. Default is 30 secs'),
  );
  $form['security']['options']['services_use_sessid'] = array(
    '#type'           => 'checkbox',
    '#title'          => t('Use sessid'),
    '#default_value'  => variable_get('services_use_sessid', TRUE),
    '#description'    => t('When enabled, all method calls must include a valid sessid. Only disable this setting if the application will user browser-based cookies.')
  );
  return $form;
}

function _services_keyauth_security_settings_validate($form_state) {
  if (isset($form_state['input']['services_key_expiry']) && !preg_match('/^\d+$/', $form_state['input']['services_key_expiry'])) {
    form_set_error('services_key_expiry', t('The token expiry time must specified in whole seconds as a number'));
  }
}

function _services_keyauth_security_settings_submit($form_state) {
  // Store all values from "our" form as variables.
  $options = _services_keyauth_security_settings();
  foreach ($options['security']['options'] as $key => $field) {
    $value = isset($form_state['input'][$key]) ? $form_state['input'][$key] : 0;
    variable_set($key, $value);
  }
}

function _services_keyauth_alter_methods(&$methods) {
  // Skip this if no services have been activated
  if (!is_array($methods) || empty($methods)) {
    return;
  }

  // sessid arg
  $arg_sessid = array(
    '#name' => 'sessid',
    '#type' => 'string',
    '#description' => t('A valid sessid.'),
  );

  $arg_domain_time_stamp = array(
    '#name' => 'domain_time_stamp',
    '#type' => 'string',
    '#description' => t('Time stamp used to hash key.'),
  );

  $arg_nonce = array(
    '#name' => 'nonce',
    '#type' => 'string',
    '#description' => t('One time use nonce also used hash key.'),
  );

  // domain arg
  $arg_domain_name = array(
    '#name' => 'domain_name',
    '#type' => 'string',
    '#description' => t('A valid domain for the API key.'),
  );

  // api_key arg
  $arg_api_key = array(
    '#name' => 'hash',
    '#type' => 'string',
    '#description' => t('A valid API key.'),
  );

  foreach ($methods as $key => &$method) {
    // set method defaults
    switch ($method['#method']) {
      case 'system.connect':
        $method['#key'] = FALSE;
        $method['#auth'] = FALSE;
        break;
      default:
        $method['#key'] = TRUE;
        $method['#auth'] = TRUE;
    }

    if ($method['#auth'] && variable_get('services_use_sessid', TRUE)) {
      array_unshift($method['#args'], $arg_sessid);
    }

    if ($method['#key'] && variable_get('services_use_key', TRUE)) {
      array_unshift($method['#args'], $arg_nonce);
      array_unshift($method['#args'], $arg_domain_time_stamp);
      array_unshift($method['#args'], $arg_domain_name);
      array_unshift($method['#args'], $arg_api_key);
    }
  }
}

function _services_keyauth_alter_browse_form(&$form, $method) {

  foreach ($method['#args'] as $key => $arg) {
    switch ($arg['#name']) {
      case 'hash':
        $form['arg'][$key] = array(
          '#title'          => 'Hash',
          '#type'           => 'textfield',
          '#value'          => t('Gets generated after form submission'),
          '#disabled'       => TRUE,
        );
        break;
      case 'sessid':
        $form['arg'][$key]['#default_value']  = session_id();
        break;
      case 'domain_name':
        $form['arg'][$key]['#default_value'] = $_SERVER['HTTP_HOST'];
        break;
      case 'domain_time_stamp':
        $form['arg'][$key] = array(
           '#title'          => 'Timestamp',
           '#type'           => 'textfield',
           '#value'          => t('Gets generated after form submission'),
           '#disabled'       => TRUE,
        );
        break;
      case 'nonce':
        $form['arg'][$key]['#default_value'] = user_password();
        break;
    }
  }
}

function _services_keyauth_authenticate_call($method, $method_name, &$args) {
  if ($method['#key'] && variable_get('services_use_key', TRUE)) {
    $hash = array_shift($args);
    $domain = array_shift($args);
    $timestamp = array_shift($args);
    $nonce = array_shift($args);

    $expiry_time = $timestamp + variable_get('services_key_expiry', 30);

    if ($expiry_time < REQUEST_TIME) {
      return services_error(t('Token has expired.'), 401);
    }
    $has_rows = (bool) db_query_range("SELECT 1 FROM {services_timestamp_nonce} WHERE domain = :domain AND nonce = :nonce", 0, 1, array(':domain' => $domain, ':nonce' => $nonce))->fetchField();

    // Still in time but has it been used before
    if ($has_rows) {
      return services_error(t('Token has been used previously for a request. Re-try with another nonce key.', 401));
    }
    else{
      db_insert('services_timestamp_nonce')
        ->fields(array('domain', 'timestamp', 'nonce'))
        ->values(array(
          'domain' => $domain,
          'timestamp' => $timestamp,
          'nonce' => $nonce,
        ))
        ->execute();
    }

    $api_key = db_query("SELECT kid FROM {services_keys} WHERE domain = :key", array(':key' => $domain))->fetchField('kid');

    //if (!services_keyauth_validate_key($api_key, $timestamp, $domain, $nonce, $method_name, $hash_parameters, $hash)) {
    if ($hash != services_get_hash($timestamp, $domain, $nonce, $method, $args)) {
      return services_error(t('Invalid API key.'), 401);
    }
    
    $has_rows = (bool) db_query_range("SELECT 1 FROM {services_key_permissions} WHERE kid = :kid AND method = :method", 0, 1, array(':kid' => $api_key, ':method' => $method_name))->fetchField();
    if (!$has_rows) {
      return services_error(t('Access denied.'), 401);
    }
  }

  // Add additonal processing for methods requiring session
  $session_backup = NULL;
  if ($method['#auth'] && variable_get('services_use_sessid', TRUE)) {
    $sessid = array_shift($args);
    if (empty($sessid)) {
      return t('Invalid sessid.');
    }
    $session_backup = services_session_load($sessid);
  }
}

function _services_keyauth_alter_browse_form_submit($method, &$args) {
  if ($method['#key'] && variable_get('services_use_key', TRUE)) {
    $args_stripped = $args;

    for ($i = 1; $i <= 4; $i++) {
      array_shift($args_stripped);
    }
    $args[2] = time();
    $args[0] = services_get_hash($args[2], $args[1], $args[3], $method, $args_stripped);
  }
}