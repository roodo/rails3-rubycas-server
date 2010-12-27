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