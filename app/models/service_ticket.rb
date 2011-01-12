#encoding: utf-8

require 'model'

class ServiceTicket < ActiveRecord::Base
  include CASServer::Model::Consumable
  
  belongs_to :granted_by_tgt,
    :class_name => 'TicketGrantingTicket',
    :foreign_key => :granted_by_tgt_id
    
  has_one :proxy_granting_ticket,
    :foreign_key => :created_by_st_id
  
  def matches_service?(service)
    CASServer::CAS.clean_service_url(self.service) == CASServer::CAS.clean_service_url(service)
  end
  
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
