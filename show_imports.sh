find . -name '*.py' | xargs grep -h 'import '|cut -d' ' -f2|sort|uniq
