#encoding: utf-8

require 'uri'
require 'net/https'
require 'model'



module CASServer::CAS
  
  include CASServer::Model

  def generate_login_ticket
    lt = LoginTicket.new
    lt.ticket = "LT-" + CASServer::Utils.random_string
    
    $LOG.debug "lt.ticket: #{lt.ticket}"
    $LOG.debug "request.env['REMOTE_ADDR']: #{request.env['REMOTE_ADDR']}"
    $LOG.debug "request.env['REMOTE_HOST']: #{request.env['REMOTE_HOST']}"
    $LOG.debug "request.env['HTTP_X_FORWARDED_FOR']: #{request.env['HTTP_X_FORWARDED_FOR']}"
    
    lt.client_hostname = request.env['HTTP_X_FORWARDED_FOR'] || request.env['REMOTE_HOST'] || request.env['REMOTE_ADDR']
    lt.save!
    $LOG.debug("Generated login ticket '#{lt.ticket}' for client" + " at '#{lt.client_hostname}'")
    return lt
  end
  
  def validate_login_ticket(ticket)
    $LOG.debug("Validating login ticket '#{ticket}'")

    success = false
    if ticket.nil?
      error = _("Your login request did not include a login ticket. There may be a problem with the authentication system.")
      $LOG.warn "Missing login ticket."
    elsif lt = LoginTicket.find_by_ticket(ticket)
      if lt.consumed?
        error = _("The login ticket you provided has already been used up. Please try logging in again.")
        $LOG.warn "Login ticket '#{ticket}' previously used up"
      #elsif Time.now - lt.created_on < settings.config[:maximum_unused_login_ticket_lifetime]
      elsif Time.now - lt.created_on < 300
        $LOG.info "Login ticket '#{ticket}' successfully validated"
      else
        error = _("You took too long to enter your credentials. Please try again.")
        $LOG.warn "Expired login ticket '#{ticket}'"
      end
    else
      error = _("The login ticket you provided is invalid. There may be a problem with the authentication system.")
      $LOG.warn "Invalid login ticket '#{ticket}'"
    end

    lt.consume! if lt

    error
  end
  
  def clean_service_url(dirty_service)
    return dirty_service if dirty_service.blank?
    clean_service = dirty_service.dup
    ['service', 'ticket', 'gateway', 'renew'].each do |p|
      clean_service.sub!(Regexp.new("&?#{p}=[^&]*"), '')
    end

    clean_service.gsub!(/[\/\?&]$/, '') # remove trailing ?, /, or &
    clean_service.gsub!('?&', '?')
    clean_service.gsub!(' ', '+')

    $LOG.debug("Cleaned dirty service URL #{dirty_service.inspect} to #{clean_service.inspect}") if dirty_service != clean_service
    return clean_service
  end
  module_function :clean_service_url

end