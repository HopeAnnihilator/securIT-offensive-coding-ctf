a = {"hi": "hi"}
a = 2
print(type(a))
match(a):
    case 1 | 2:
        print('error')
    case {'h': 'hi'}:
        print('dict')
    case _:
        print(a)
