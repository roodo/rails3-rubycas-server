# encoding: utf-8

require "log4r"
require 'log4r/formatter/patternformatter'



CONFIG_FILE = ENV['CONFIG_FILE'] || "#{::Rails.root.to_s}/config/cas.yml"


RoodoCasServer::Application.config.cas_config = HashWithIndifferentAccess.new(
  :maximum_unused_login_ticket_lifetime => 5.minutes,
  :maximum_unused_service_ticket_lifetime => 5.minutes, # CAS Protocol Spec, sec. 3.2.1 (recommended expiry time)
  :maximum_session_lifetime => 1.month                  # all tickets are deleted after this period of time
)
CasConf = RoodoCasServer::Application.config.cas_config


def load_config_file(config_file)
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
  
  CasConf.merge! HashWithIndifferentAccess.new(YAML.load(config_file))
end

def init_logger 
  Rails.logger = Log4r::Logger.new("")
  #Rails.logger.trace = true
  
  if CasConf[:log_level]
    case CasConf[:log_level].upcase
      when "DEBUG"  
        Rails.logger.level = Log4r::DEBUG    
      when "INFO"   
        Rails.logger.level = Log4r::INFO
      when "WARN"   
        Rails.logger.level = Log4r::WARN
      when "ERROR"  
        Rails.logger.level = Log4r::ERROR
      when "FATAL"  
        Rails.logger.level = Log4r::FATAL        
    end
  else
    Rails.logger.level = Log4r::WARN
  end
  
  # Log4r::StderrOutputter.new "console"
  Log4r::FileOutputter.new("logfile", 
    :filename => "log/#{RAILS_ENV}.log", 
    :trunc => true,
    :trace => true,
    :formatter => Log4r::PatternFormatter.new(:pattern => "[%d] %5l -- : %1M"))
    #:formatter => Log4r::PatternFormatter.new(:pattern => "[%d] %t %5l -- : %1M"))
    
  Rails.logger.add("logfile")
end


def init_authenticators
  auth = []
  
  begin
    # attempt to instantiate the authenticator
    CasConf[:authenticator] = [CasConf[:authenticator]] unless CasConf[:authenticator].instance_of? Array
    CasConf[:authenticator].each { |authenticator|
      auth << authenticator[:class].constantize
    }
  rescue NameError
    if CasConf[:authenticator].instance_of? Array
      CasConf[:authenticator].each do |authenticator|
        if !authenticator[:source].nil?
          # config.yml explicitly names source file
          require authenticator[:source]
        else
          # the authenticator class hasn't yet been loaded, so lets try to load it from the lib/authenticators directory
          auth_rb = authenticator[:class].underscore.gsub('cas_server/', '')
          require auth_rb
        end
        auth << authenticator[:class].constantize
      end
    else
      if config[:authenticator][:source]
        # config.yml explicitly names source file
        require CasConf[:authenticator][:source]
      else
        # the authenticator class hasn't yet been loaded, so lets try to load it from the lib/authenticators directory
        auth_rb = CasConf[:authenticator][:class].underscore.gsub('cas_server/', '')
        require auth_rb
      end

      auth << CasConf[:authenticator][:class].constantize
      CasConf[:authenticator] = [CasConf[:authenticator]]
    end
  end

  auth.zip(CasConf[:authenticator]).each_with_index{ |auth_conf, index|
    authenticator, conf = auth_conf
    Rails.logger.debug "About to setup #{authenticator} with #{conf.inspect}..."
    authenticator.setup(conf.merge('auth_index' => index)) if authenticator.respond_to?(:setup)
    Rails.logger.debug "Done setting up #{authenticator}."
  }

  RoodoCasServer::Application.config.auth = auth
end



load_config_file(CONFIG_FILE)
init_logger
init_authenticators
Auth = RoodoCasServer::Application.config.auth

