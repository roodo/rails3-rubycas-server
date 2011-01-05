# Load the rails application
require File.expand_path('../application', __FILE__)
require 'casclient'
require 'casclient/frameworks/rails/filter'
    
# Initialize the rails application
RoodoCasServer::Application.initialize!

# Configure rubycas-client
# CASClient::Frameworks::Rails::Filter.configure(
#   :cas_base_url => "http://localhost:3000/",
#   :login_url    => "http://localhost:3000/server/index",
#   :logout_url   => "http://cas.example.foo/server/logout",
#   :username_session_key => :cas_user,
#   :extra_attributes_session_key => :cas_extra_attributes,
#   :authenticate_on_every_request => true
# )