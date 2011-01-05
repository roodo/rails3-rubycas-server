# encoding: utf-8

require "utils"
require "cas"


class ServerController < ApplicationController

  include CASServer::CAS
 
  # before_filter CASClient::Frameworks::Rails::Filter, :only => [ :demo ]
  before_filter :set_settings
  
  def set_settings
    response.headers['Content-Type'] = 'text/html; charset=UTF-8'
    @theme = CasConf[:theme] if CasConf[:theme]
    @organization = CasConf[:organization] if CasConf[:organization]
    @infoline = CasConf[:infoline] if CasConf[:infoline]
  end
  
  def index
    CASServer::Utils::log_controller_action(self.class, params)

    # make sure there's no caching
    response.headers['Pragma'] = 'no-cache'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Expires'] = (Time.now - 1.year).rfc2822
    
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
          Rails.logger.debug service_with_ticket
          redirect_to service_with_ticket, :status => 303 # response code 303 means "See Other" (see Appendix B in CAS Protocol spec)
        elsif @gateway
          Rails.logger.debug("Redirecting unauthenticated gateway request to service '#{@service}'.")
          redirect_to @service, :status => 303
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
    @username = params['username']
    @password = params['password']
    @lt = params['lt']

    # Remove leading and trailing widespace from username.
    @username.strip! if @username
    
    if @username && CasConf[:downcase_username]
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
    Rails.logger.debug("Logging in with username: #{@username}, lt: #{@lt}, service: #{@service}, auth: #{Auth.inspect}")
    
    credentials_are_valid = false
    extra_attributes = {}
    successful_authenticator = nil
    begin
      auth_index = 0
      Auth.each do |auth_class|
        auth = auth_class.new
        auth_config = CasConf[:authenticator][auth_index]
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

    if credentials_are_valid
      Rails.logger.info("Credentials for username '#{@username}' successfully validated using #{successful_authenticator.class.name}.")
      Rails.logger.debug("Authenticator provided additional user attributes: #{extra_attributes.inspect}") unless extra_attributes.blank?

      # 3.6 (ticket-granting cookie)
      tgt = generate_ticket_granting_ticket(@username, extra_attributes)

      if CasConf[:maximum_session_lifetime]
        expires = CasConf[:maximum_session_lifetime].to_i.from_now
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
        Rails.logger.info("Successfully authenticated user '#{@username}' at '#{tgt.client_hostname}'. No service param was given, so we will redirect to demo page.")
        @message = {:type => 'confirmation', :message => "You have successfully logged in."}
        return redirect_to :action => "demo"
      else
        @st = generate_service_ticket(@service, @username, tgt)

        begin
          service_with_ticket = service_uri_with_ticket(@service, @st)

          Rails.logger.info("Redirecting authenticated user '#{@username}' at '#{@st.client_hostname}' to service '#{@service}'")
          #redirect service_with_ticket, 303 # response code 303 means "See Other" (see Appendix B in CAS Protocol spec)
          return redirect_to service_with_ticket, :status => 303
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

    return render :index
  end

  def logout
    CASServer::Utils::log_controller_action(self.class, params)

    # The behaviour here is somewhat non-standard. Rather than showing just a blank
    # "logout" page, we take the user back to the login page with a "you have been logged out"
    # message, allowing for an opportunity to immediately log back in. This makes it
    # easier for the user to log out and log in as someone else.
    @service = clean_service_url(params['service'] || params['destination'])
    @continue_url = params['url']
    @gateway = params['gateway'] == 'true' || params['gateway'] == '1'

    tgt = CASServer::Model::TicketGrantingTicket.find_by_ticket(request.cookies['tgt'])
    response.delete_cookie 'tgt'

    if tgt
      CASServer::Model::TicketGrantingTicket.transaction do
        Rails.logger.debug("Deleting Service/Proxy Tickets for '#{tgt}' for user '#{tgt.username}'")
        tgt.granted_service_tickets.each do |st|
          send_logout_notification_for_service_ticket(st) if config[:enable_single_sign_out]
          # TODO: Maybe we should do some special handling if send_logout_notification_for_service_ticket fails?
          #       (the above method returns false if the POST results in a non-200 HTTP response).
          Rails.logger.debug "Deleting #{st.class.name.demodulize} #{st.ticket.inspect} for service #{st.service}."
          st.destroy
        end

        pgts = CASServer::Model::ProxyGrantingTicket.find(:all,
          :conditions => [CASServer::Model::Base.connection.quote_table_name(CASServer::Model::ServiceTicket.table_name)+".username = ?", tgt.username],
          :include => :service_ticket)
        pgts.each do |pgt|
          Rails.logger.debug("Deleting Proxy-Granting Ticket '#{pgt}' for user '#{pgt.service_ticket.username}'")
          pgt.destroy
        end

        Rails.logger.debug("Deleting #{tgt.class.name.demodulize} '#{tgt}' for user '#{tgt.username}'")
        tgt.destroy
      end

      Rails.logger.info("User '#{tgt.username}' logged out.")
    else
      Rails.logger.warn("User tried to log out without a valid ticket-granting ticket.")
    end

    @message = {:type => 'confirmation', :message => "You have successfully logged out."}

    @message[:message] += " Please click on the following link to continue:" if @continue_url

    @lt = generate_login_ticket

    if @gateway && @service
      return redirect @service, :status => 303
    elsif @continue_url
      return render :logout
    else
      return render :login
    end
  end
  
  def demo
  end
  
  def validate
    CASServer::Utils::log_controller_action(self.class, params)
      
    # required
    @service = clean_service_url(params['service'])
    @ticket = params['ticket']
    
    # optional
    @renew = params['renew']
    
    st, @error = validate_service_ticket(@service, @ticket)      
    @success = st && !@error
    @username = st.username if @success

    render :validate, :layout => false, :status => response_status_from_error(@error) if @error
  end
  
  def serviceValidate 
    CASServer::Utils::log_controller_action(self.class, params)

    # required
    @service = clean_service_url(params['service'])
    @ticket = params['ticket']
    
    # optional
    @renew = params['renew']

    st, @error = validate_service_ticket(@service, @ticket)
    @success = st && !@error
    if @success
      @username = st.username
      if @pgt_url
        pgt = generate_proxy_granting_ticket(@pgt_url, st)
        @pgtiou = pgt.iou if pgt
      end
      @extra_attributes = st.granted_by_tgt.extra_attributes || {}
    end

    render :proxy_validate, :layout => false, :status => response_status_from_error(@error) if @error
  end
  
  def proxyValidate
    CASServer::Utils::log_controller_action(self.class, params)

    # required
    @service = clean_service_url(params['service'])
    @ticket = params['ticket']
    
    # optional
    @pgt_url = params['pgtUrl']
    @renew = params['renew']

    @proxies = []

    t, @error = validate_proxy_ticket(@service, @ticket)
    @success = t && !@error

    @extra_attributes = {}
    if @success
      @username = t.username

      if t.kind_of? CASServer::Model::ProxyTicket
        @proxies << t.granted_by_pgt.service_ticket.service
      end

      if @pgt_url
        pgt = generate_proxy_granting_ticket(@pgt_url, t)
        @pgtiou = pgt.iou if pgt
      end

      @extra_attributes = t.granted_by_tgt.extra_attributes || {}
    end

    status response_status_from_error(@error) if @error

   render :builder, :proxy_validate
  end
  
  def proxy
  end
  
  def response_status_from_error(error)
    case error.code.to_s
    when /^INVALID_/, 'BAD_PGT'
      422
    when 'INTERNAL_ERROR'
      500
    else
      500
    end
  end

  def serialize_extra_attribute(builder, value)
    if value.kind_of?(String)
      builder.text! value
    elsif value.kind_of?(Numeric)
      builder.text! value.to_s
    else
      builder.cdata! value.to_yaml
    end
  end
  
end
