FROM osixia/openldap:1.5.0

# Only schema files into schema/custom
COPY schema/ /container/service/slapd/assets/config/bootstrap/schema/custom/

# Only *data* LDIFs into ldif/custom (adjust the names below!)
COPY seed/ /container/service/slapd/assets/config/bootstrap/ldif/custom/