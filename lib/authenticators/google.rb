require 'authenticators/base'
require 'uri'
require 'net/http'
require 'net/https'
require 'timeout'

# Validates Google accounts against Google's authentication service -- in other
# words, this authenticator allows users to log in to CAS using their
# Gmail/Google accounts.
class CASServer::Authenticators::Google < CASServer::Authenticators::Base
  def validate(credentials)
    read_standard_credentials(credentials)
    return false if @username.blank? || @password.blank?

    auth_data = {
      'Email'   => @username,
      'Passwd'  => @password,
      'service' => 'xapi',
      'source'  => 'RubyCAS-Server',
      'accountType' => 'HOSTED_OR_GOOGLE'
    }
    
    url = URI.parse('https://www.google.com/accounts/ClientLogin')
    if CasConf[:proxy_host]
      Rails.logger.debug("proxy_host: #{CasConf[:proxy_host]}")
      Rails.logger.debug("proxy_port: #{CasConf[:proxy_port]}")
      Rails.logger.debug("proxy_username: #{CasConf[:proxy_username]}")
      Rails.logger.debug("proxy_password: #{CasConf[:proxy_password]}")
      
      http = Net::HTTP.Proxy(
        CasConf[:proxy_host], 
        CasConf[:proxy_port], 
        CasConf[:proxy_username], 
        CasConf[:proxy_password]).new(url.host, url.port)
    else
      Rails.logger.debug("url.host: #{url.host}, url.port: #{url.port}")
      http = Net::HTTP.new(url.host, url.port)
    end
    http.use_ssl = true

    # TODO: make the timeout configurable
    wait_seconds = 10
    begin
      timeout(wait_seconds) do
        res = http.start do |conn|
          req = Net::HTTP::Post.new(url.path)
          req.set_form_data(auth_data,'&')
          conn.request(req)
        end

        case res
        when Net::HTTPSuccess
          true
        when Net::HTTPForbidden
          false
        else
          Rails.logger.error("Unexpected response from Google while validating credentials: #{res.inspect} ==> #{res.body}.")
          raise CASServer::AuthenticatorError, "Unexpected response received from Google while validating credentials."
        end
      end
    rescue Timeout::Error
      Rails.logger.error("Google did not respond to the credential validation request. We waited for #{wait_seconds.inspect} seconds before giving up.")
      raise CASServer::AuthenticatorError, "Timeout while waiting for Google to validate credentials."
    end

  end
end
