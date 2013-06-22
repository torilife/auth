<?php

namespace Auth;

class NormalUserUpdateException extends \FuelException {}

class NormalUserWrongPassword extends \FuelException {}

/**
 * NormalAuth basic login driver
 *
 * @package     Fuel
 * @subpackage  Auth
 */
class Auth_Login_Normalauth extends \Auth_Login_Driver
{

	public static function _init()
	{
		\Config::load('normalauth', true);
	}

	/**
	 * @var  Database_Result  when login succeeded
	 */
	protected $member = null;

	/**
	 * @var  array  NormalAuth class config
	 */
	protected $config = array(
//		'drivers' => array('group' => array('NormalGroup')),
	);

	/**
	 * Check for login
	 *
	 * @return  bool
	 */
	protected function perform_check()
	{
		$member_id  = \Session::get('member_id');
		$login_hash = \Session::get('login_hash');

		// only worth checking if there's both a member_id and login-hash
		if (!empty($member_id) and !empty($login_hash))
		{
			if (is_null($this->member) or $this->member['id'] != $member_id)
			{
				$this->member = self::get_member4id($member_id);
			}

			// return true when login was verified
			if ($this->member and $this->member['login_hash'] === $login_hash)
			{
				return true;
			}
		}

		\Session::delete('member_id');
		\Session::delete('login_hash');

		return false;
	}

	/**
	 * Login user
	 *
	 * @param   string
	 * @param   string
	 * @return  bool
	 */
	public function login($email = '', $password = '')
	{
		$email    = trim($email)    ? trim($email)    : trim(\Input::post(\Config::get('normalauth.username_post_key', 'email')));
		$password = trim($password) ? trim($password) : trim(\Input::post(\Config::get('normalauth.password_post_key', 'password')));

		if (empty($email) or empty($password))
		{
			return false;
		}

		$password = $this->hash_password($password);
		$member_auth = \DB::select_array(array('*'))
			->where('email', '=', $email)
			->and_where('password', '=', $password)
			->from('member_auth')
			->execute(\Config::get('normalauth.db_connection'))->current();

		if ($member_auth == false)
		{
			\Session::delete('member_id');
			\Session::delete('login_hash');

			return false;
		}
		$this->member = self::get_member4id($member_auth['member_id']);

		\Session::set('member_id', $member_auth['member_id']);
		\Session::set('login_hash', $this->create_login_hash());
		\Session::instance()->rotate();

		return true;
	}

	/**
	 * Force login user
	 *
	 * @param   string
	 * @return  bool
	 */
	public function force_login($member_id = '')
	{
		if (empty($member_id))
		{
			return false;
		}

		$this->member = \DB::select_array(array('*'))
				 ->where('id', '=', $member_id)
				 ->from('member')
				 ->execute(\Config::get('normalauth.db_connection'))
				 ->current();

		if ($this->member == false)
		{
			\Session::delete('member_id');
			\Session::delete('login_hash');

			return false;
		}

		\Session::set('member_id', $this->member['id']);
		\Session::set('login_hash', $this->create_login_hash());
		return true;
	}

	/**
	 * Logout user
	 *
	 * @return  bool
	 */
	public function logout()
	{
		\Session::delete('member_id');
		\Session::delete('login_hash');

		return true;
	}

	/**
	 * Create new user
	 *
	 * @param   string  must contain valid email address
	 * @param   string
	 * @param   string
	 * @return  bool
	 */
	public function create_user($email, $password, $name = '')
	{
		$password = trim($password);
		$email = filter_var(trim($email), FILTER_VALIDATE_EMAIL);

		if (empty($password) or empty($email))
		{
			throw new \NormalUserUpdateException('Email address and password can\'t be empty.');
		}

		$same_users = \DB::select_array(array('*'))
			->where('email', '=', $email)
			->from('member_auth')
			->execute(\Config::get('normalauth.db_connection'));

		if ($same_users->count() > 0)
		{
			if (in_array(strtolower($email), array_map('strtolower', $same_users->current())))
			{
				throw new \NormalUserUpdateException('Email address already exists');
			}
		}

		try
		{
			\DB::start_transaction();

			$member = array(
				'created_at' => date('Y-m-d H:i:s'),
				'updated_at' => date('Y-m-d H:i:s'),
			);
			if ($name) $member['name'] = $name;
			$member_id = self::db_insert('member', $member);

			$member_auth = array(
				'member_id'  => (int)$member_id,
				'email'      => $email,
				'password'   => $this->hash_password((string) $password),
				'created_at' => date('Y-m-d H:i:s'),
				'updated_at' => date('Y-m-d H:i:s'),
			);
			$this->db_insert('member_auth', $member_auth);
			\DB::commit_transaction();
		}
		catch (Exception $e)
		{
			\DB::rollback_transaction();

			return false;
		}

		return $member_id;
	}

	/**
	 * Update a user's properties
	 * Note: Username cannot be updated, to update password the old password must be passed as old_password
	 *
	 * @param   Array  properties to be updated including profile fields
	 * @param   string
	 * @return  bool
	 */
	public function update_user($values, $member_id = null)
	{
		if (empty($member_id)) $member_id = $this->member['id'];
		if (empty($member_id))
		{
			throw new \NormalUserUpdateException('Member_id is empty.');
		}

		$current_values = \DB::select_array(array('*'))
			->where('member_id', '=', $member_id)
			->from('member_auth')
			->execute(\Config::get('normalauth.db_connection'));

		if (empty($current_values))
		{
			throw new \NormalUserUpdateException('Member_id not found');
		}

		$update = array();
		if (array_key_exists('password', $values))
		{
			if (empty($values['old_password'])
				or $current_values->get('password') != $this->hash_password(trim($values['old_password'])))
			{
				throw new \NormalUserWrongPassword('Old password is invalid');
			}

			$password = trim(strval($values['password']));
			if ($password === '')
			{
				throw new \NormalUserUpdateException('Password can\'t be empty.');
			}
			$update['password'] = $this->hash_password($password);
			unset($values['password']);
		}
		if (array_key_exists('old_password', $values))
		{
			unset($values['old_password']);
		}
		if (array_key_exists('email', $values))
		{
			$email = filter_var(trim($values['email']), FILTER_VALIDATE_EMAIL);
			if ( ! $email)
			{
				throw new \NormalUserUpdateException('Email address is not valid');
			}
			if (\Util_db::check_record_exist('member_auth', 'email', $email))
			{
				throw new \NormalUserUpdateException('Email address is already exists.');
			}
			$update['email'] = $email;
			unset($values['email']);
		}

		$affected_rows = \DB::update('member_auth')
			->set($update)
			->where('member_id', '=', $member_id)
			->execute(\Config::get('normalauth.db_connection'));

		// Refresh user
		if ($this->member['id'] == $member_id)
		{
			$this->member = self::get_member4id($member_id);
		}

		return $affected_rows > 0;
	}

	/**
	 * Change a user's password
	 *
	 * @param   string
	 * @param   string
	 * @param   string  username or null for current user
	 * @return  bool
	 */
	public function change_password($old_password, $new_password, $member_id = null)
	{
		try
		{
			return (bool) $this->update_user(array('old_password' => $old_password, 'password' => $new_password), $member_id);
		}
		// Only catch the wrong password exception
		catch (NormalUserWrongPassword $e)
		{
			return false;
		}
	}

	/**
	 * Generates new random password, sets it for the given username and returns the new password.
	 * To be used for resetting a user's forgotten password, should be emailed afterwards.
	 *
	 * @param   string  $username
	 * @return  string
	 */
	public function reset_password($member_id)
	{
		$new_password = \Str::random('alnum', 8);
		$this->change_password_simple($new_password);

		return $new_password;
	}

	public function change_password_simple($member_id, $new_password)
	{
		$password_hash = $this->hash_password($new_password);

		$affected_rows = \DB::update('member_auth')
			->set(array('password' => $password_hash))
			->where('member_id', '=', $member_id)
			->execute(\Config::get('normalauth.db_connection'));

		if ( ! $affected_rows)
		{
			throw new \NormalUserUpdateException('Failed to reset password, user was invalid.');
		}

		return $new_password;
	}

	/**
	 * Deletes a given user
	 *
	 * @param   string
	 * @return  bool
	 */
	public function delete_user($member_id)
	{
		if (empty($member_id))
		{
			throw new \NormalUserUpdateException('Cannot delete user with empty member_id');
		}

		$affected_rows = \DB::delete('member')
			->where('id', '=', $member_id)
			->execute(\Config::get('normalauth.db_connection'));

		return $affected_rows > 0;
	}

	/**
	 * Creates a temporary hash that will validate the current login
	 *
	 * @return  string
	 */
	public function create_login_hash()
	{
		if (empty($this->member))
		{
			throw new \NormalUserUpdateException('User not logged in, can\'t create login hash.');
		}

		$last_login = date('Y-m-d H:i:s');
		$login_hash = sha1(\Config::get('normalauth.login_hash_salt').$this->member['id'].$last_login);

		\DB::update('member')
			->set(array('last_login' => $last_login, 'login_hash' => $login_hash))
			->where('id', '=', $this->member['id'])
			->execute(\Config::get('normalauth.db_connection'));

		$this->member['login_hash'] = $login_hash;

		return $login_hash;
	}

	/**
	 * Get the member's ID
	 *
	 * @return  integer
	 */
	public function get_member_id()
	{
		if (empty($this->member))
		{
			return false;
		}

		return (int)$this->member['id'];
	}

	/**
	 * Get the user's ID
	 *
	 * @return  Array  containing this driver's ID & the user's ID
	 */
	public function get_user_id()
	{
		if (empty($this->member))
		{
			return false;
		}

		return array($this->id, (int) $this->member['id']);
	}

	/**
	 * Get the user's emailaddress
	 *
	 * @return  string
	 */
	public function get_email()
	{
		if (empty($this->member))
		{
			return false;
		}

		return $this->member['email'];
	}

	/**
	 * Get the user's screen name
	 *
	 * @return  string
	 */
	public function get_screen_name()
	{
		if (empty($this->member))
		{
			return false;
		}

		return $this->member['name'];
	}

	/**
	 * Extension of base driver method to default to user group instead of user id
	 */
//	public function has_access($condition, $driver = null, $user = null)
//	{
//		if (is_null($user))
//		{
//			$groups = $this->get_groups();
//			$user = reset($groups);
//		}
//		return parent::has_access($condition, $driver, $user);
//	}

	public function get_groups()
	{
	}

	/**
	 * Check password
	 *
	 * @param   string
	 * @return  bool
	 */
	public function check_password($password = '')
	{
		if (!$this->perform_check()) return false;

		$member_id = \Session::get('member_id');
		$password = trim($password) ? trim($password) : trim(\Input::post(\Config::get('normalauth.password_post_key', 'password')));
		if (empty($member_id) || empty($password)) return false;

		return (bool)\DB::select_array(array('*'))
			->where('member_id', '=', $member_id)
			->and_where('password', '=', $this->hash_password($password))
			->from('member_auth')
			->execute(\Config::get('normalauth.db_connection'))->current();
	}

	private static function get_member4id($id)
	{
		return \DB::select_array(array('member.*', 'member_auth.email'))
			->from('member')
			->join('member_auth','LEFT')->on('member_auth.member_id', '=', 'member.id')
			->where('member.id', '=', $id)
			->execute(\Config::get('normalauth.db_connection'))->current();
	}

	private static function db_insert($table, array $values)
	{
		$data['created_at'] = date('Y-m-d H:i:s');
		$data['updated_at'] = date('Y-m-d H:i:s');
		$result = \DB::insert($table)
							->set($values)
							->execute(\Config::get('normalauth.db_connection'));
		if (!($result[1] > 0))
		{
			throw new Exception(sprintf('Insert error. (table:%s)', $table));
		}

		return $result[0];
	}

	/**
	 * Perform the actual login check
	 *
	 * @return  bool
	 */
	public function validate_user()
	{
	}
}

// end of file normalauth.php
