require_relative 'inotify_sys'

# Extends the INotify class to implement more advanced
# (and fiber-friendly) functionality
class INotify < IO
  #EVENTS = []

  # def create_fd() -> T_FIXNUM

  def initialize
    @watches = {}

    # c-implemented wrapper for inotify_init syscall
    # pass to IO#initialize to handle all the complex stuff
    super(create_fd)
  end

  Event = Struct.new :watch, :events, :cookie, :name

  def add_watch(path, events)
    # convert to mask add watch to inotify fd
    mask = events2mask Array(events)
    id = add_watch_mask(path, mask)
    
    # record and return watch record
    base = @watches.fetch(id, Watch.new(id, path, []))
    base.events += events

    @watches[id] = base
  end

  def rm_watch(watch)
    raise ArgumentError.new "Expecting a Watch object" unless watch.is_a? Watch
    
    unless @watches.delete(watch)
      raise ArgumentError.new "Watch '#{watch.id}' not found"
    end

    rm_watch_id(watch.id)
  end

  def next_event(block = true)
    
  end

  # def read() -> T_ARRAY
  # def read_nonblock() -> T_ARRAY

  # private
  # def add_watch_mask
  # def rm_watch_id
  # def event_mask
end
