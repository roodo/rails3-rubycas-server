#encoding: utf-8

require 'model'

class LoginTicket < ActiveRecord::Base
  include CASServer::Model::Consumable
  
  def to_s
    ticket
  end

  def self.cleanup(max_lifetime)
    transaction do
      conditions = ["created_on < ?", Time.now - max_lifetime]
      expired_tickets_count = count(:conditions => conditions)

      Rails.logger.debug("Destroying #{expired_tickets_count} expired #{self.name.demodulize}"+
        "#{'s' if expired_tickets_count > 1}.") if expired_tickets_count > 0

      destroy_all(conditions)
    end
  end
end
