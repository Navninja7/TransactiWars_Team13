FROM php:8.2-apache

# Install required PHP extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql
RUN a2enmod rewrite headers reqtimeout ssl

RUN apt-get update && apt-get install -y \
    libpng-dev libjpeg-dev libwebp-dev libzip-dev openssl && \
    docker-php-ext-configure gd --with-jpeg --with-webp && \
    docker-php-ext-install gd zip && \
    rm -rf /var/lib/apt/lists/*

# Generate self-signed SSL certificate
RUN mkdir -p /etc/ssl/certs /etc/ssl/private && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/selfsigned.key \
    -out /etc/ssl/certs/selfsigned.crt \
    -subj "/CN=localhost"

COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf

# SECURITY: Hardened PHP configuration
RUN { \
    echo "upload_max_filesize = 4M"; \
    echo "post_max_size = 6M"; \
    echo "session.cookie_httponly = 1"; \
    echo "session.use_strict_mode = 1"; \
    echo "session.cookie_samesite = Strict"; \
    echo "session.gc_maxlifetime = 1800"; \
    echo "expose_php = Off"; \
    echo "display_errors = Off"; \
    echo "display_startup_errors = Off"; \
    echo "log_errors = On"; \
    echo "error_log = /var/log/apache2/php_error.log"; \
    echo "allow_url_fopen = Off"; \
    echo "allow_url_include = Off"; \
    echo "file_uploads = On"; \
    echo "max_execution_time = 30"; \
    echo "memory_limit = 128M"; \
    echo "max_input_vars = 100"; \
    echo "max_input_time = 30"; \
    echo "max_input_nesting_level = 3"; \
    echo "post_max_size = 8M"; \
    echo "enable_dl = Off"; \
    echo "cgi.force_redirect = 1"; \
    echo "session.use_trans_sid = 0"; \
    echo "session.use_only_cookies = 1"; \
    echo "session.sid_length = 64"; \
    echo "session.sid_bits_per_character = 6"; \
    echo "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,phpinfo,proc_get_status,proc_nice,proc_terminate,getmyuid,getmypid,leak,listen,diskfreespace,tmpfile,link,ignore_user_abort,highlight_file,dl,set_time_limit,source,show_source,fpassthru"; \
} >> /usr/local/etc/php/php.ini

# SECURITY: Remove PHP version from Apache headers
RUN echo "ServerTokens Prod" >> /etc/apache2/apache2.conf && \
    echo "ServerSignature Off" >> /etc/apache2/apache2.conf && \
    echo "TraceEnable off" >> /etc/apache2/apache2.conf

# Copy source files
COPY src/ /var/www/html/

# Create uploads directory with secure permissions
RUN mkdir -p /var/www/html/uploads/profiles && \
    chown -R www-data:www-data /var/www/html && \
    chmod -R 750 /var/www/html && \
    chmod -R 770 /var/www/html/uploads

EXPOSE 80
EXPOSE 443
CMD ["apache2-foreground"]
