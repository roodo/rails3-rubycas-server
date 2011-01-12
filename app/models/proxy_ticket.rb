#encoding: utf-8

require 'service_ticket'

class ProxyTicket < ServiceTicket
  belongs_to :granted_by_pgt,
    :class_name => 'ProxyGrantingTicket',
    :foreign_key => :granted_by_pgt_id
end