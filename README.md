# BinjaScripts

Heavily inspired by the work by Aaron Portnoy and arizvisa on [using IDA Pro as a Data Store](https://www.youtube.com/watch?v=A4yXdir_59E#).

## Features

Shortened API for faster Binja terminal hacking..

```
f - current_function
llil - current_function.low_level_il
llilssa - current_function.low_level_il.ssa_form
mlil - current_function.medium_level_il
mlilssa - current_function.medium_level_il.ssa_form
```

### Tag system

Creating new tags

```
tags.add(address, tagname, data)
```

Querying existing tags

```
tags.select(tagname)
tags.select(address)
tags.select(address, tagname)
tags.select(tagname, address)
```

## Building the docs

```
pip install sphinx
```

```
sphinx-apidoc -f -o docs/source/ .; cd docs/; make clean; make html; cd ..
```

## License

This plugin is released under a [MIT](LICENSE) license.
