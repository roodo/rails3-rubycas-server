# encoding: utf-8

require "utils"
require "cas"


class ServerController < ApplicationController
  include CASServer::CAS
  
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
          $LOG.info("User '#{tgt.username}' authenticated based on ticket granting cookie. Redirecting to service '#{@service}'.")
          redirect service_with_ticket, 303 # response code 303 means "See Other" (see Appendix B in CAS Protocol spec)
        elsif @gateway
          $LOG.info("Redirecting unauthenticated gateway request to service '#{@service}'.")
          redirect @service, 303
        end
      elsif @gateway
          $LOG.error("This is a gateway request but no service parameter was given!")
          @message = {
            :type => 'mistake',
            :message => _("The server cannot fulfill this gateway request because no service parameter was given.")
          }
      end
    rescue URI::InvalidURIError
      $LOG.error("The service '#{@service}' is not a valid URI!")
      @message = {
        :type => 'mistake',
        :message => _("The target service your browser supplied appears to be invalid. Please contact your system administrator for help.")
      }
    end

    lt = generate_login_ticket

    $LOG.debug("Rendering login form with lt: #{lt}, service: #{@service}, renew: #{@renew}, gateway: #{@gateway}")

    @lt = lt.ticket

    $LOG.debug(env)
  end

  def login
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
