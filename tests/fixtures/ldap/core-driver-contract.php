<?php
// A scripted interface double, not a copy of REDCap's licensed driver. Real revisions are tested separately.
class Auth_Container_LDAP {
    public static $authenticate;
    public static $constructed=[];
    public $options, $_auth_obj, $conn_id=false;
    function __construct($config) {
        self::$constructed[]=$config;
        $this->options=array_replace(['version'=>2,'start_tls'=>false,'attrformat'=>'AUTH','url'=>''],$config);
    }
    function fetchData($username,$password) { return (self::$authenticate)($this,$username,$password); }
}
class PEAR_Error {
    private $message;
    function __construct($message) { $this->message=$message; }
    function getMessage() { return $this->message; }
    function getCode() { return 41; }
}
class PEAR { static function isError($value) { return $value instanceof PEAR_Error; } }
