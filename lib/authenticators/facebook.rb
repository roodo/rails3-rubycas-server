#encoding: utf-8

require 'authenticators/base'
require 'digest/sha1'
require 'digest/sha2'
require 'crypt-isaac'



class CASServer::Authenticators::Facebook

  def validate(credentials)
    results = User.find(:all, :conditions => ["email = ?", credentials[:email]])
    User.connection_pool.checkin(User.connection)
    
    if results.size > 0      
      return true
    else
      return false
    end
  end

end
