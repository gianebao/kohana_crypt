<?php defined('SYSPATH') OR die('No direct script access.');

/**
 * Encryption with tamper-validation signature.
 *
 */
class Crypt_Core {
    
    /**
     * @var  string  default instance name
     */
    public static $default = 'default';
    
    /**
     * @var  array  Crypt class instances
     */
    public static $instances = array();

    /**
     * @var  string  OS-dependent RAND type to use
     */
    protected static $_rand;

    /**
     * Returns a singleton instance of Encrypt. An encryption key must be
     * provided in your "encrypt" configuration file.
     *
     *     $encrypt = Crypt::instance();
     *
     * @param   string  $name   configuration group name
     * @return  Crypt
     */
    public static function instance($name = NULL)
    {
        if ($name === NULL)
        {
            // Use the default instance name
            $name = Crypt::$default;
        }

        if (isset(Crypt::$instances[$name]))
        {
            return Crypt::$instances[$name];
        }
        
        // Load the configuration data
        $config = Kohana::$config->load('crypt')->$name;

        if ( ! isset($config['key']))
        {
            // No default encryption key is provided!
            throw new Kohana_Exception('No encryption key is defined in the encryption configuration group: :group',
                array(':group' => $name));
        }

        if ( ! isset($config['mode']))
        {
            // Add the default mode
            $config['mode'] = MCRYPT_MODE_NOFB;
        }

        if ( ! isset($config['cipher']))
        {
            // Add the default cipher
            $config['cipher'] = MCRYPT_RIJNDAEL_128;
        }
        
        if ( ! isset($config['delimiter']))
        {
            // Add the default cipher
            $config['delimiter'] = '.';
        }

        if ( ! isset($config['hash_algo']))
        {
            // Add the default cipher
            $config['hash_algo'] = 'sha256';
        }
        
        if (empty($config['sign_salt']))
        {
            // No tamper salt
            throw new Kohana_Exception('No encryption salt signature is defined in the encryption configuration group: :group',
                array(':group' => $name));
        }
        
        // Create a new instance
        return Crypt::$instances[$name] = new Crypt($config['key'], $config['mode'], $config['cipher'], $config['hash_algo'], $config['sign_salt'], $config['delimiter']);
    }

    /**
     * Creates a new mcrypt wrapper.
     *
     * @param   string  $key       encryption key
     * @param   string  $mode      mcrypt mode
     * @param   string  $hash_algo hash algorithm
     * @param   string  $sign_salt hash salt
     * @param   string  $delimiter signature delimiter
     */
    public function __construct($key, $mode, $cipher, $hash_algo, $sign_salt, $delimiter)
    {
        // Find the max length of the key, based on cipher and mode
        $size = mcrypt_get_key_size($cipher, $mode);

        if (isset($key[$size]))
        {
            // Shorten the key to the maximum size
            $key = substr($key, 0, $size);
        }

        // Store the key, mode, and cipher
        $this->_key    = $key;
        $this->_mode   = $mode;
        $this->_cipher = $cipher;
        $this->_hash_algo = $hash_algo;
        $this->_sign_salt = $sign_salt;
        $this->_delimiter = $delimiter;

        // Store the IV size
        $this->_iv_size = mcrypt_get_iv_size($this->_cipher, $this->_mode);
    }

    /**
     * Encrypts a string and returns an encrypted string that can be decoded.
     *
     *     $data = $encrypt->encode($data);
     *
     * The encrypted binary data is encoded using [base64](http://php.net/base64_encode)
     * to convert it to a string. This string can be stored in a database,
     * displayed, and passed using most other means without corruption.
     *
     * @param   string  $data   data to be encrypted
     * @return  string
     */
    public function encode($data)
    {
        // Set the rand type if it has not already been set
        if (Crypt::$_rand === NULL)
        {
            if (Kohana::$is_windows)
            {
                // Windows only supports the system random number generator
                Crypt::$_rand = MCRYPT_RAND;
            }
            else
            {
                if (defined('MCRYPT_DEV_URANDOM'))
                {
                    // Use /dev/urandom
                    Crypt::$_rand = MCRYPT_DEV_URANDOM;
                }
                elseif (defined('MCRYPT_DEV_RANDOM'))
                {
                    // Use /dev/random
                    Crypt::$_rand = MCRYPT_DEV_RANDOM;
                }
                else
                {
                    // Use the system random number generator
                    Crypt::$_rand = MCRYPT_RAND;
                }
            }
        }

        if (Crypt::$_rand === MCRYPT_RAND)
        {
            // The system random number generator must always be seeded each
            // time it is used, or it will not produce true random results
            mt_srand();
        }

        // Create a random initialization vector of the proper size for the current cipher
        $iv = mcrypt_create_iv($this->_iv_size, Crypt::$_rand);
        
        // Add a signature of the data
        $salt = strtolower(hash($this->_hash_algo, $this->_sign_salt . $data));
        
        // Encrypt the data using the configured options and generated iv
        $data = mcrypt_encrypt($this->_cipher, $this->_key, $data, $this->_mode, $iv);

        // Use base64 encoding to convert to a string
        return base64_encode($salt) . $this->_delimiter .  base64_encode($iv.$data);
    }

    /**
     * Decrypts an encoded string back to its original value.
     *
     *     $data = $encrypt->decode($data);
     *
     * @param   string  $data   encoded string to be decrypted
     * @return  FALSE   if decryption fails
     * @return  string
     */
    public function decode($data)
    {
        $data = explode($this->_delimiter, $data);
    
        if (count($data) === 2)
        {
            return false;
        }
        
        $sign = base64_decode($data[0]);
        
        // Convert the data back to binary
        $data = base64_decode($data[1], TRUE);

        if ( ! $data)
        {
            // Invalid base64 data
            return FALSE;
        }
        
        // Extract the initialization vector from the data
        $iv = substr($data, 0, $this->_iv_size);

        if ($this->_iv_size !== strlen($iv))
        {
            // The iv is not the expected size
            return FALSE;
        }

        // Remove the iv from the data
        $data = substr($data, $this->_iv_size);

        // Return the decrypted data, trimming the \0 padding bytes from the end of the data
        $data = rtrim(mcrypt_decrypt($this->_cipher, $this->_key, $data, $this->_mode, $iv), "\0");
        
        // Check if data was tampered
        if (strtolower(hash($this->_hash_algo, $this->_sign_salt . $data)) == $sign)
        {
            // Not tampered.
            return $data;
        }
        
        return false;
    }

}