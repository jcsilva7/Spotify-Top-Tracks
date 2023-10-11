#tão aqui algumas cenas mais recentes no caderno tá:tipos/f-string/type casting/string methods/user input/funções matemáticas
import math

#ladoM= float(input("Qual é o comprimento em cm do lado maior do triângulo?: "))
#ladom= float(input("Qual é o comprimento em cm do lado menor do triângulo?: "))
#hip= math.sqrt(pow(ladoM,2)+pow(ladom,2))
#print(hip)

#pi=3.14
#raio=float(input("Qual é o raio do círculo?: "))
#area= pi*pow(raio,2)
#print(area)

#age=18
#print(f"Eu tenho {age} anos")

#nome = "José Silva"
#primeiro_nome = nome[:4]
#apelido= nome[5:]
#hehehe = nome[::3]
#nome_contrario = nome[::-1]
#print(nome_contrario)

#website = "http://youtube.com"
#website2 = "http://yahoo.com"
#slice = slice(7,-4)
#website[slice]
#print(website2[slice])

#idade = int(input("Qual é a tua idade?: "))
#if idade >=110:
     #print("Já devias tar morto!")
#elif idade >= 65:
    #print("És um velho!")
#elif idade >= 18 and idade < 65:
    #print("És um adulto!")
#elif idade < 0 :
    #print("Vai mentir pro carago!")
#elif idade > 65:
    #print("És um idoso!")
#elif idade < 5:
    #print("És um bebé, nem sabes ler isto...")
#else:
    #print("És um puto!")

#if not(temp >=0 and temp <=30):
    #print("Vai para a rua!")
#elif not(temp<0 or temp>0):
   #print("Hoje a temperatura tá má!")
    #print("Na rua não tá agradável!")

#nome = ""
#while len(nome) == 0:
    #nome = input("Qual é o teu nome?: ")

#print(f"Olá sr.{nome}")

#nome = None
#while not nome:
    #nome = input("Nome?: ")

#print(f"O teu nome é {nome}")

#for i in range(10):
    #print(i+1)
#for i in range(5,20+1,2):
    #print(i)

#for i in "José Silva":
    #print(i)

#import time
#for segundos in range(10,0,-1):
   # print(segundos)
 #   time.sleep(1)
#print("KABOOM")

#nested loops
#columns = int(input("How many columns do you want?: "))
#rows = int(input("How many rows do you want?: "))
#symbol = input("Which symbol do you wish to use?: ")

#for i in range(rows):
     #for j in range(columns):
          #print(symbol, end = "")
     #print()

#break continue e pass
while True:
     name = input("Enter your name: ")
     if name != "":
          break     

phone_number = "193-348-2424"

for i in phone_number:
     if i == "-":
          continue
     print(i, end="")
     
for i in range(1,21):
     if i == 13:
          pass
     else:
          print(i)