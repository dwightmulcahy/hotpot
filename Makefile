.PHONY: test compile check run build clean

test:
	python -m unittest discover -s tests -v

compile:
	python -m compileall -q hotpot tests

check: compile test

run:
	python -m hotpot.app

build:
	docker build -t hotpot:local .

clean:
	find hotpot tests -type d -name __pycache__ -prune -exec rm -rf {} +
	find hotpot tests -type f -name '*.py[co]' -delete
