# encoding: utf-8

require "utils"
require "cas"
# require "authenticators/base"
# require "authenticators/sql"


class ServerController < ApplicationController
  CONFIG_FILE = ENV['CONFIG_FILE'] || "config/cas.yml"
  
  include CASServer::CAS
  
  @@app_file = __FILE__ 
  @@public = File.expand_path(File.dirname(__FILE__)+"/../../public")
  
  config = HashWithIndifferentAccess.new(
    :maximum_unused_login_ticket_lifetime => 5.minutes,
    :maximum_unused_service_ticket_lifetime => 5.minutes, # CAS Protocol Spec, sec. 3.2.1 (recommended expiry time)
    :maximum_session_lifetime => 1.month,                 # all tickets are deleted after this period of time
    :log => {
        :file => 'casserver.log', 
        :level => 'DEBUG'},
    :uri_path => ""
  )
  @@config = config
  
  def self.uri_path
    @@config[:uri_path]
  end
  
  def self.load_config_file(config_file)
    begin
      config_file = File.open(config_file)
    rescue Errno::ENOENT => e
      $stderr.puts
      $stderr.puts "!!! Config file #{config_file.inspect} does not exist!"
      $stderr.puts
      raise e
    rescue Errno::EACCES => e
      $stderr.puts
      $stderr.puts "!!! Config file #{config_file.inspect} is not readable (permission denied)!"
      $stderr.puts
      raise e
    rescue => e
      $stderr.puts
      $stderr.puts "!!! Config file #{config_file.inspect} could not be read!"
      $stderr.puts
      raise e
    end
    
    @@config.merge! HashWithIndifferentAccess.new(YAML.load(config_file))
  end
  
  def self.reconfigure!(config)
    config.each do |key, val|
      @@config[key] = val
    end

    init_logger!
    init_authenticators!
  end
  
  def self.handler_ssl_options
    return {} unless @config[:ssl_cert]

    cert_path = @config[:ssl_cert]
    key_path = @config[:ssl_key] || @config[:ssl_cert]
    
    unless cert_path.nil? && key_path.nil?
      raise Error, "The ssl_cert and ssl_key options cannot be used with mongrel. You will have to run your " +
        " server behind a reverse proxy if you want SSL under mongrel." if
          @@config[:server] == 'mongrel'

      raise Error, "The specified certificate file #{cert_path.inspect} does not exist or is not readable. " +
        " Your 'ssl_cert' configuration setting must be a path to a valid " +
        " ssl certificate." unless
          File.exists? cert_path

      raise Error, "The specified key file #{key_path.inspect} does not exist or is not readable. " +
        " Your 'ssl_key' configuration setting must be a path to a valid " +
        " ssl private key." unless
          File.exists? key_path

      require 'openssl'
      require 'webrick/https'

      cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
      key = OpenSSL::PKey::RSA.new(File.read(key_path))

      {
        :SSLEnable        => true,
        :SSLVerifyClient  => ::OpenSSL::SSL::VERIFY_NONE,
        :SSLCertificate   => cert,
        :SSLPrivateKey    => key
      }
    end
  end
  
  def self.init_authenticators!
    auth = []
    
    begin
      # attempt to instantiate the authenticator
      @@config[:authenticator] = [@@config[:authenticator]] unless @@config[:authenticator].instance_of? Array
      @@config[:authenticator].each { |authenticator|
        auth << authenticator[:class].constantize
      }
    rescue NameError
      if @@config[:authenticator].instance_of? Array
        @@config[:authenticator].each do |authenticator|
          if !authenticator[:source].nil?
            # config.yml explicitly names source file
            require authenticator[:source]
          else
            # the authenticator class hasn't yet been loaded, so lets try to load it from the casserver/authenticators directory
            auth_rb = authenticator[:class].underscore.gsub('cas_server/', '')
            require auth_rb
          end
          auth << authenticator[:class].constantize
        end
      else
        if config[:authenticator][:source]
          # config.yml explicitly names source file
          require @@config[:authenticator][:source]
        else
          # the authenticator class hasn't yet been loaded, so lets try to load it from the casserver/authenticators directory
          auth_rb = @@config[:authenticator][:class].underscore.gsub('cas_server/', '')
          require auth_rb
        end

        auth << @@config[:authenticator][:class].constantize
        @@config[:authenticator] = [@@config[:authenticator]]
      end
    end

    auth.zip(@@config[:authenticator]).each_with_index{ |auth_conf, index|
      authenticator, conf = auth_conf
      Rails.logger.debug "About to setup #{authenticator} with #{conf.inspect}..."
      authenticator.setup(conf.merge('auth_index' => index)) if authenticator.respond_to?(:setup)
      Rails.logger.debug "Done setting up #{authenticator}."
    }

    @@auth = auth
  end
  
  def self.init_logger!
    if @@config[:log]
      if @@config[:log][:file]
        Rails.logger.debug "Redirecting log to #{@@config[:log][:file]}"
        Rails.logger = Logger.new(@@config[:log][:file])
      end
      Rails.logger.debug "TEST"
      Rails.logger.level = Logger.const_get(@@config[:log][:level]) if @@config[:log][:level]
    end
  end
  
  configure do
    load_config_file(CONFIG_FILE)
    init_logger!
    init_authenticators!
  end
  
  def index
    CASServer::Utils::log_controller_action(self.class, params)
    
    # make sure there's no caching
    headers['Pragma'] = 'no-cache'
    headers['Cache-Control'] = 'no-store'
    headers['Expires'] = (Time.now - 1.year).rfc2822
    
    # optional params
    @service = clean_service_url(params['service'])
    @renew = params['renew']
    @gateway = params['gateway'] == 'true' || params['gateway'] == '1'
    
    if tgc = request.cookies['tgt']
      tgt, tgt_error = validate_ticket_granting_ticket(tgc)
    end
    
    if tgt and !tgt_error
      @message = {
        :type => 'notice',
        :message => "You are currently logged in as '%s'. If this is not you, please log in below." % tgt.username 
      }
    end
    
    if params['redirection_loop_intercepted']
      @message = {
        :type => 'mistake',
        :message => "The client and server are unable to negotiate authentication. Please try logging in again later."
      }
    end
    
    begin
      if @service
        if !@renew && tgt && !tgt_error
          st = generate_service_ticket(@service, tgt.username, tgt)
          service_with_ticket = service_uri_with_ticket(@service, st)
          Rails.logger.debug("User '#{tgt.username}' authenticated based on ticket granting cookie. Redirecting to service '#{@service}'.")
          redirect service_with_ticket, 303 # response code 303 means "See Other" (see Appendix B in CAS Protocol spec)
        elsif @gateway
          Rails.logger.debug("Redirecting unauthenticated gateway request to service '#{@service}'.")
          redirect @service, 303
        end
      elsif @gateway
          Rails.logger.debug("This is a gateway request but no service parameter was given!")
          @message = {
            :type => 'mistake',
            :message => "The server cannot fulfill this gateway request because no service parameter was given."
          }
      end
    rescue URI::InvalidURIError
      Rails.logger.debug("The service '#{@service}' is not a valid URI!")
      @message = {
        :type => 'mistake',
        :message => "The target service your browser supplied appears to be invalid. Please contact your system administrator for help."
      }
    end
    
    lt = generate_login_ticket
    Rails.logger.debug("Rendering login form with lt: #{lt}, service: #{@service}, renew: #{@renew}, gateway: #{@gateway}")
    @lt = lt.ticket
  end

  def login
    CASServer::Utils::log_controller_action(self.class, params)
    
    # 2.2.1 (optional)
    @service = clean_service_url(params['service'])

    # 2.2.2 (required)
    @username = params['email']
    @password = params['password']
    @lt = params['lt']

    # Remove leading and trailing widespace from username.
    @username.strip! if @username
    
    if @username && @@config[:downcase_username]
      Rails.logger.debug("Converting username #{@username.inspect} to lowercase because 'downcase_username' option is enabled.")
      @username.downcase!
    end

    if error = validate_login_ticket(@lt)
      @message = {:type => 'mistake', :message => error}
      # generate another login ticket to allow for re-submitting the form
      @lt = generate_login_ticket.ticket
      return render :index, :status => 401
    end
    
    # generate another login ticket to allow for re-submitting the form after a post
    @lt = generate_login_ticket.ticket
    Rails.logger.debug("Logging in with username: #{@username}, lt: #{@lt}, service: #{@service}, auth: #{@@auth.inspect}")
    
    credentials_are_valid = false
    extra_attributes = {}
    successful_authenticator = nil
    begin
      auth_index = 0
      @@auth.each do |auth_class|
        auth = auth_class.new

        auth_config = @@config[:authenticator][auth_index]
        # pass the authenticator index to the configuration hash in case the authenticator needs to know
        # it splace in the authenticator queue
        auth.configure(auth_config.merge('auth_index' => auth_index))

        credentials_are_valid = auth.validate(
          :username => @username,
          :password => @password,
          :service => @service,
          :request => @env
        )
        if credentials_are_valid
          extra_attributes.merge!(auth.extra_attributes) unless auth.extra_attributes.blank?
          successful_authenticator = auth
          break
        end

        auth_index += 1
      end
    rescue CASServer::AuthenticatorError => e
      Rails.logger.debug(e)
      @message = {:type => 'mistake', :message => e.to_s}
      return render :index
    end
    
    Rails.logger.debug credentials_are_valid
    if credentials_are_valid
      Rails.logger.info("Credentials for username '#{@username}' successfully validated using #{successful_authenticator.class.name}.")
      Rails.logger.debug("Authenticator provided additional user attributes: #{extra_attributes.inspect}") unless extra_attributes.blank?

      # 3.6 (ticket-granting cookie)
      tgt = generate_ticket_granting_ticket(@username, extra_attributes)

      if @@config[:maximum_session_lifetime]
        expires     = @@config[:maximum_session_lifetime].to_i.from_now
        expiry_info = " It will expire on #{expires}."

        response.set_cookie('tgt', {
          :value => tgt.to_s,
          :expires => expires
        })
      else
        expiry_info = " It will not expire."
        response.set_cookie('tgt', tgt.to_s)
      end

      Rails.logger.debug("Ticket granting cookie '#{request.cookies['tgt'].inspect}' granted to #{@username.inspect}. #{expiry_info}")

      if @service.blank?
        Rails.logger.info("Successfully authenticated user '#{@username}' at '#{tgt.client_hostname}'. No service param was given, so we will not redirect.")
        @message = {:type => 'confirmation', :message => _("You have successfully logged in.")}
      else
        @st = generate_service_ticket(@service, @username, tgt)

        begin
          service_with_ticket = service_uri_with_ticket(@service, @st)

          Rails.logger.info("Redirecting authenticated user '#{@username}' at '#{@st.client_hostname}' to service '#{@service}'")
          redirect service_with_ticket, 303 # response code 303 means "See Other" (see Appendix B in CAS Protocol spec)
        rescue URI::InvalidURIError
          Rails.logger.error("The service '#{@service}' is not a valid URI!")
          @message = {
            :type => 'mistake',
            :message => "The target service your browser supplied appears to be invalid. Please contact your system administrator for help."
          }
        end
      end
    else
      Rails.logger.warn("Invalid credentials given for user '#{@username}'")
      @message = {:type => 'mistake', :message => "Incorrect username or password."}
      return render :index, :status => 401
    end

    render :index
  end

  def logout
  end
  
  def validate
  end
  
  def serviceValidate 
  end
  
  def proxyValidate
  end
  
  def proxy
  end
  
end
