#encoding: utf-8

require 'authenticators/base'
require 'uri'
require 'net/http'
require 'net/https'
require 'timeout'
require 'gdata'

# Validates Google accounts against Google's authentication service -- in other
# words, this authenticator allows users to log in to CAS using their Gmail/Google accounts.
class CASServer::Authenticators::Google < CASServer::Authenticators::Base

  def validate(credentials)
    read_standard_credentials(credentials)
    raise_if_not_configured

    Rails.logger.debug "@username: #{@username}"
    Rails.logger.debug "@password: #{@password}"
    
    begin    
      client_login_handler = GData::Auth::ClientLogin.new('writely', :account_type => 'HOSTED')
      
      token = client_login_handler.get_token(@username, @password, 'google-RailsArticleSample-v1')
      Rails.logger.debug "google token: #{token}"
      
      client = GData::Client::Base.new(:auth_handler => client_login_handler)
    rescue
      return false
    end
    
    return true
  end
  
  def raise_if_not_configured
    raise CASServer::AuthenticatorError.new(
      "Cannot validate credentials because the authenticator hasn't yet been configured"
    ) unless @options
  end
  
end