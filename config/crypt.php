<?php defined('SYSPATH') OR die('No direct script access.');


return array (
    'default' => array (
        // Mcrypt key
        'key'        => 'SOMEmcryptKEy',
        
        // Mcrypt mode constant. [http://php.net/manual/en/mcrypt.constants.php]
        // 'mode'       => MCRYPT_MODE_NOFB,
        
        // Mcrypt cypher constant. [http://www.php.net/manual/en/mcrypt.ciphers.php]
        // 'cipher'     => MCRYPT_RIJNDAEL_128,
        
        // Hash algorithm
        // 'hash_algo'  => 'sha256',
        
        // Delimiter for signature and payload. Use 1 puctuation character.
        // If not sure, you can leave it as default
        // 'delimiter'  => '.',
        
        // Hash salt for the signature
        'sign_salt'  => 'AntherSaltSignatureTHATYouNeedToChange',
    )
);