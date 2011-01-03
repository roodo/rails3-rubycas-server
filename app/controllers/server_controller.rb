# encoding: utf-8

require "utils"
require "cas"
require "authenticators/base"
require "authenticators/sql"


class ServerController < ApplicationController
  include CASServer::CAS
  CONFIG_FILE = "config/cas.yml"
  
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
    
    config.merge! HashWithIndifferentAccess.new(YAML.load(config_file))
    #set :server, config[:server] || 'webrick'
  end
  
  configure do
    load_config_file(CONFIG_FILE)
    #init_logger!
    #init_database!
    #init_authenticators!
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
        :message => _("You are currently logged in as '%s'. If this is not you, please log in below.") % tgt.username 
      }
    end

    if params['redirection_loop_intercepted']
      @message = {
        :type => 'mistake',
        :message => _("The client and server are unable to negotiate authentication. Please try logging in again later.")
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
            :message => _("The server cannot fulfill this gateway request because no service parameter was given.")
          }
      end
    rescue URI::InvalidURIError
      Rails.logger.debug("The service '#{@service}' is not a valid URI!")
      @message = {
        :type => 'mistake',
        :message => _("The target service your browser supplied appears to be invalid. Please contact your system administrator for help.")
      }
    end

    lt = generate_login_ticket

    Rails.logger.debug("Rendering login form with lt: #{lt}, service: #{@service}, renew: #{@renew}, gateway: #{@gateway}")

    @lt = lt.ticket

    #$LOG.debug(env)
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
    
    #if @username && settings.config[:downcase_username]
    if @username
      Rails.logger.debug("Converting username #{@username.inspect} to lowercase because 'downcase_username' option is enabled.")
      @username.downcase!
    end

    if error = validate_login_ticket(@lt)
      @message = {:type => 'mistake', :message => error}
      # generate another login ticket to allow for re-submitting the form
      @lt = generate_login_ticket.ticket
      @status = 401
      Rails.logger.debug("Logging in with username: #{@username}, lt: #{@lt}, message: #{@message}, status: #{@status}")
      #render :erb, :index
      return render :index
    end
    
    # generate another login ticket to allow for re-submitting the form after a post
    @lt = generate_login_ticket.ticket
    #$LOG.debug("Logging in with username: #{@username}, lt: #{@lt}, service: #{@service}, auth: #{settings.auth.inspect}")
    Rails.logger.debug("Logging in with username: #{@username}, lt: #{@lt}, service: #{@service}")
    
    credentials_are_valid = false
    # extra_attributes = {}
    successful_authenticator = nil
    begin
      # auth_index = 0
      # settings.auth.each do |auth_class|
      #   auth = auth_class.new
      # 
      #   auth_config = settings.config[:authenticator][auth_index]
      #   # pass the authenticator index to the configuration hash in case the authenticator needs to know
      #   # it splace in the authenticator queue
      #   auth.configure(auth_config.merge('auth_index' => auth_index))
      # 
      #   credentials_are_valid = auth.validate(
      #     :username => @username,
      #     :password => @password,
      #     :service => @service,
      #     :request => @env
      #   )
      #   if credentials_are_valid
      #     extra_attributes.merge!(auth.extra_attributes) unless auth.extra_attributes.blank?
      #     successful_authenticator = auth
      #     break
      #   end
      # 
      #   auth_index += 1
      # end
      
      # auth = CASServer::Authenticators::SQL.new
      # auth_config = settings.config[:authenticator][auth_index]
      # auth.configure(auth_config.merge('auth_index' => auth_index))
      
      results = Users.find(:all, :conditions => ["account = ? AND password = ?", @username, @password])
      if results.size > 0
        credentials_are_valid = true
      else
        credentials_are_valid = false
      end
    rescue CASServer::AuthenticatorError => e
      $LOG.error(e)
      @message = {:type => 'mistake', :message => e.to_s}
      return render(:index)
    end
    
    if credentials_are_valid
      extra_attributes = {}
      tgt = generate_ticket_granting_ticket(@username, extra_attributes)
      
      #expires = settings.config[:maximum_session_lifetime].to_i.from_now
      expires = 172800.to_i.from_now
      expiry_info = " It will expire on #{expires}."

      response.set_cookie('tgt', {
        :value => tgt.to_s,
        :expires => expires
      })
      
      Rails.logger.debug("Ticket granting cookie '#{request.cookies['tgt'].inspect}' granted to #{@username.inspect}. #{expiry_info}")
      
      if @service.blank?
        Rails.logger.info("Successfully authenticated user '#{@username}' at '#{tgt.client_hostname}'. No service param was given, so we will not redirect.")
        # @message = {:type => 'confirmation', :message => _("You have successfully logged in.")}
        @message = {:type => 'confirmation', :message => "You have successfully logged in."}
      else
        @st = generate_service_ticket(@service, @username, tgt)
        begin
          service_with_ticket = service_uri_with_ticket(@service, @st)
          Rails.logger.info("Redirecting authenticated user '#{@username}' at '#{@st.client_hostname}' to service '#{@service}'")
          redirect service_with_ticket, 303 # response code 303 means "See Other" (see Appendix B in CAS Protocol spec)
        rescue URI::InvalidURIError
          $LOG.error("The service '#{@service}' is not a valid URI!")
          @message = {
            :type => 'mistake',
            #:message => _("The target service your browser supplied appears to be invalid. Please contact your system administrator for help.")
            :message => "The target service your browser supplied appears to be invalid. Please contact your system administrator for help."
          }
        end
      end
    else
      Rails.logger.warn("Invalid credentials given for user '#{@username}'")
      #@message = {:type => 'mistake', :message => _("Incorrect username or password.")}
      @message = {:type => 'mistake', :message => "Incorrect username or password."}
      @status = 401
      #render :file => "public/401.html", :status => 401
    end
    
    #render :erb, :index
    Rails.logger.info("message: '#{@message}'")
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
