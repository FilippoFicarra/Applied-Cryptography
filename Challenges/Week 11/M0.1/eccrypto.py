from __future__ import annotations
from Crypto.PublicKey import ECC

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        if isinstance(other, EllipticCurvePoint):
            return self.x == other.x and self.y == other.y
        return False

class EllipticCurve:
    CurveList = {
        "secp256k1": {
            "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
            "a": 0x0000000000000000000000000000000000000000000000000000000000000000,
            "b": 0x0000000000000000000000000000000000000000000000000000000000000007,
            "G": (
                0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
            ),
            "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            "h": 0x1,
        },
        "secp256r1": {
            "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
            "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
            "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
            "G": (
                0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
            ),
            "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
            "h": 0x1,
        },
    }

    def __init__(self, curve_name):
        self.curve_name = curve_name
        assert curve_name in self.CurveList
        curve = self.CurveList[curve_name]
        self.G = EllipticCurvePoint(self, curve["G"][0], curve["G"][1])
        self.p = curve["p"]
        self.n = curve["n"]
        self.a = curve["a"]
        self.b = curve["b"]
        self.zero = EllipticCurvePoint(self, 0, 0)

    def point(self, x, y) -> EllipticCurvePoint:
        return EllipticCurvePoint(self, x, y)
    
class EllipticCurvePointInf(Point):

    def __init__(self, curve: EllipticCurve):
        self.curve = curve

    def is_equal_curve(self, other):
        if not isinstance(other, EllipticCurvePointInf):
            return False
        return self.curve.a == other.curve.a and self.curve.b == other.curve.b and self.curve.p == other.curve.p


    def negate(self):
        # Write a function that negates a PointInf object.        
        # Ths is an optional extension and is not evaluated
        return self

    def double(self):
        # Write a function that doubles a PointInf object.
        return self   

    def add(self, other):
        # Write a function that adds a Point object (or a PointInf object) to a PointInf object. 
        # See below for the description of a Point object
        # Make sure to output the correct kind of object depending on whether "other" is a Point object or a PointInf object 
        if self.x == other.x and self.y == other.y:
            return self
        return other

class EllipticCurvePoint(Point):
    def __init__(self, curve: EllipticCurve, x, y):
        self.curve = curve
        super().__init__(x, y)

    def __eq__(self, other):
        if isinstance(other, EllipticCurvePoint):
            return super(EllipticCurvePoint, self).__eq__(other)
        return False

    def __repr__(self):
        return f"Point({self.x}, {self.y})"

    def double(self) -> EllipticCurvePoint:
        """
        Your code goes here.
        """
        Lambda = ((3*(self.x**2)%self.curve.p +self.curve.a)%self.curve.p * pow(2*self.y,-1, self.curve.p))%self.curve.p
        xPrime = ((Lambda**2)%self.curve.p-2*self.x)%self.curve.p
        yPrime = (-(self.y+Lambda*(xPrime-self.x)))%self.curve.p
        return EllipticCurvePoint(self.curve, xPrime, yPrime)
    
    def negate(self):
        return EllipticCurvePoint(self.curve, self.x, -self.y)

        
    def add(self, Q: EllipticCurvePoint) -> EllipticCurvePoint:
        """
        Your code goes here.
        """

        if isinstance(Q, EllipticCurvePointInf) :
            return self
        if self.x == Q.x and self.y == Q.y:
            return self.double()
        if self.x ==Q.negate() and self.y == Q.negate().y:
            return EllipticCurvePointInf(self.curve)

        y1=self.y
        y2=Q.y
        x1=self.x
        x2=Q.x
        Lambda = ((y1-y2)%self.curve.p * pow((x1-x2),-1,  self.curve.p))%self.curve.p
        xPrime = ((Lambda**2)%self.curve.p - x1 - x2)%self.curve.p
        yPrime = (-(y1+Lambda*(xPrime-x1)))%self.curve.p

        return EllipticCurvePoint(self.curve, xPrime, yPrime)



if __name__ == '__main__':
    ec = EllipticCurve('secp256r1')
    P = ec.point(97888558776977767929139598212151244375624093967957786381607156262397400025189, 70260250667642441997625718220391089091961309752586883122805246884540651437086)
    Q = ec.point(113553925975488117103196701471510411175915875085453160324179604321619831108304, 23961092807730593536583075333242735054758214742412484520420323992915614314302)

    P_test = ECC.EccPoint(P.x, P.y, curve='secp256r1')
    Q_test = ECC.EccPoint(Q.x, Q.y, curve='secp256r1')

    assert (P_test + Q_test).x ==  P.add(Q).x
    assert (P_test + Q_test).y ==  P.add(Q).y

    ec = EllipticCurve('secp256k1')
    P = ec.point(107303582290733097924842193972465022053148211775194373671539518313500194639752, 103795966108782717446806684023742168462365449272639790795591544606836007446638)
    Q = ec.point(36034668029310999675425029227919426304128362788024891102120850317866231552679,  81120990977494636963407451456021843404486499021598452981689548730055179196713)

    """
    Compute the flag EC point: P + P + Q.
    Note that EC point addition formulas may not work to add a point to itself!
    """
    flag = P.add(P).add(Q)

    print(flag)

