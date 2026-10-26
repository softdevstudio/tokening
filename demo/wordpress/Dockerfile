FROM wordpress:6.9.4-php8.3-apache
ADD --checksum=sha256:c8bc28f83d3c39beffa2add4f6becc0b1ae54097df433697d1dbe6520a80d769 https://github.com/WordPress/mcp-adapter/releases/download/v0.7.1/mcp-adapter.zip /tmp/mcp-adapter.zip
RUN php -r '$z = new ZipArchive(); if ($z->open("/tmp/mcp-adapter.zip") !== true || !$z->extractTo("/usr/src/wordpress/wp-content/plugins")) { exit(1); } $z->close();' && rm /tmp/mcp-adapter.zip
COPY tokening-demo.php /usr/src/wordpress/wp-content/mu-plugins/tokening-demo.php
COPY seed.php verify.php /opt/tokening/
RUN php -l /usr/src/wordpress/wp-content/mu-plugins/tokening-demo.php && php -l /opt/tokening/seed.php && php -l /opt/tokening/verify.php
