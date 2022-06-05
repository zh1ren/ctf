# Great sources: https://www.youtube.com/watch?v=C6abHMw8uoo&ab_channel=AndrewMcCrady
#                https://ctf101.org/cryptography/what-is-rsa/

def ffm(n):
    # Fermat Factorization Method
    t = Integer(ceil(sqrt(n)))
    while True:
        s = sqrt(t^2 - n)
        if s == int(s):
            # s is an integer
            p = t + s
            q = t - s
            return (p,q)
        
        t += 1

print(ffm(9379104451666902807254251547664494589376537004464676565187690588653871658978822987097064298936295147221139510534805502109113119601614394205797875059439905610480321353589582133110727481084808437441842912190040256221115163284631623589000119654843098091251164625806009940056025960835406998838387521455069967004404011645684521669329210152867128697650117219793408414423485717757224152576433432244378386973038733036305783601847652110678653741642215483011184789551861027169721217226927325340419066252945574407810391883801428118671134092909741227928016626842719456736068380990227433485001024796590524675348060787126908578087))
