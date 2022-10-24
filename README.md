# PyFormHunter

![PyFormHunter](https://i.imgur.com/Ts08spu.png)

This is the pythonic version of [FormHunter](https://github.com/edo0xff/FormHunter).

Small command line tool for HTTP Post (Web forms, like login forms) interception written in Python. This tool by itself only sniffs your own machine network traffic but you can perform an arpspoof attack (using another tools) to intercept and look for HTTP Posts in all the local network traffic.

## Config

All requeriments are listed on `requirements.txt` and can be installed with pip by running:

```bash
$ pip install -r requirements.txt
```

## Usage

The command line receives one required argument and one optional argument: `python main.py -i <IFACE> -f <Comma,separated,form,input,names,to,filter>`, eg.:

```bash
$ python main.py -i eth0
```

or filtering form inputs that contains the words `user` or `password`:

```bash
$ python main.py -i eth0 -f user,password
```

## Known Limitations

1. This program does not support HTTPs packets capture although its support should be easy to implement (perfoming an SSLStrip attack).

## License

MIT