#encoding: utf-8


module CASServer
  module Cas
    def generate_login_ticket
      lt = LoginTicket.new
      lt.ticket = "LT-" + CASServer::Utils.random_string
  
      lt.client_hostname = @env['HTTP_X_FORWARDED_FOR'] || @env['REMOTE_HOST'] || @env['REMOTE_ADDR']
      lt.save!
      $LOG.debug("Generated login ticket '#{lt.ticket}' for client" +
        " at '#{lt.client_hostname}'")
      lt
    end
  
    # Strips CAS-related parameters from a service URL and normalizes it,
    # removing trailing / and ?. Also converts any spaces to +.
    #
    # For example, "http://google.com?ticket=12345" will be returned as
    # "http://google.com". Also, "http://google.com/" would be returned as
    # "http://google.com".
    #
    # Note that only the first occurance of each CAS-related parameter is
    # removed, so that "http://google.com?ticket=12345&ticket=abcd" would be
    # returned as "http://google.com?ticket=abcd".
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
end