# REDCap Survey Auth

A REDCap External Module that adds authentication to surveys.

CURRENTLY NOT IN A WORKING STATE!


## Other LDAP configuration

Configuration information has to be provided as a JSON string and in form of an array. Thus, multiple LDAP configurations can be provided, which will be checked in the given order. Use this following template, which follows closely the LDAP configuration in REDCap's `webtoolsl2/ldap` folder. Currently, `attributes`, `userfilter`, and `referrals` are not used.

```JSON
[
    {
        "url": "ldap://127.0.0.1",
        "port": 389,
        "version": 3,
        "basedn": "...",
        "binddn": "bindUsername",
        "bindpw": "bindpassword",
        "attributes": [],
        "userattr": "samAccountName",
        "userfilter": "(objectCategory=person)",
        "start_tls": false,
        "referrals": false
    }
]
```

