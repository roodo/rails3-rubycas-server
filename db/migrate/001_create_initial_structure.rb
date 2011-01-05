#encoding: utf-8



class CreateInitialStructure < ActiveRecord::Migration
  def self.up
    create_table 'casserver_lts', :force => true do |t|
      t.string    'ticket',          :null => false
      t.timestamp 'created_on',      :null => false
      t.datetime  'consumed',        :null => true
      t.string    'client_hostname', :null => false
    end

    create_table 'casserver_sts', :force => true do |t|
      t.string    'ticket',            :null => false
      t.text      'service',           :null => false
      t.timestamp 'created_on',        :null => false
      t.datetime  'consumed',          :null => true
      t.string    'client_hostname',   :null => false
      t.string    'username',          :null => false
      t.string    'type',              :null => false
      t.integer   'granted_by_pgt_id', :null => true
      t.integer   'granted_by_tgt_id', :null => true
    end

    create_table 'casserver_tgts', :force => true do |t|
      t.string    'ticket',           :null => false
      t.timestamp 'created_on',       :null => false
      t.string    'client_hostname',  :null => false
      t.string    'username',         :null => false
      t.text      'extra_attributes', :null => true
    end

    create_table 'casserver_pgts', :force => true do |t|
      t.string    'ticket',            :null => false
      t.timestamp 'created_on',        :null => false
      t.string    'client_hostname',   :null => false
      t.string    'iou',               :null => false
      t.integer   'service_ticket_id', :null => false
    end
    
    create_table 'users', :force => true do |t|
      t.string     'email',      :null => false
      t.string     'password',   :null => false
      t.string     'nickname',   :null => false
      t.string     'birthday',   :null => false
      t.timestamps 'created_at', :null => false
      t.timestamps 'updated_at', :null => false
    end
  end

  def self.down
    drop_table 'casserver_pgt'
    drop_table 'casserver_tgt'
    drop_table 'casserver_st'
    drop_table 'casserver_lt'
    drop_table 'user'
  end 
end
