#encoding: utf-8

require 'model'

class TicketGrantingTicket < ActiveRecord::Base
  include CASServer::Model::Consumable

  serialize :extra_attributes

  has_many :granted_service_tickets,
    :class_name => 'ServiceTicket',
    :foreign_key => :granted_by_tgt_id
    
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
