require_relative 'inotify_sys'

class INotify < IO
  class Watch
    attr_reader :id, :path, :events

    def initialize(id, path, events)
      @id = id
      @path = path
      @events = events
    end

    def add_events(*ev)

    end
  end
end
