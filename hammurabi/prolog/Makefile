CC=swipl
DEPS = $(shell find static -type f)

all: bin/firefox bin/chrome

bin/firefox: $(DEPS)
	@mkdir -p bin
	$(CC) '--goal=load_files('facts', [stream(user_input), optimise(true)])' -O -o $@ -c static/firefox.pl

bin/chrome: $(DEPS)
	@mkdir -p bin
	$(CC) '--goal=load_files('facts', [stream(user_input), optimise(true)])' -O -o $@ -c static/chrome.pl

clean:
	rm -f bin/*
