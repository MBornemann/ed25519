import CEd25519

public final class PublicKey {
    private let buffer: [UInt8]
    
    public convenience init(_ bytes: [UInt8]) throws {
        guard bytes.count == 32 else {
            throw Ed25519Error.invalidPublicKeyLength
        }
        
        self.init(unchecked: bytes)
    }
    
    init(unchecked buffer: [UInt8]) {
        self.buffer = buffer
    }
    
    public var bytes: [UInt8] {
        return buffer
    }

    public func verify(signature: [UInt8], message: [UInt8]) throws -> Bool {
        guard signature.count == 64 else {
            throw Ed25519Error.invalidSignatureLength
        }

        return signature.withUnsafeBufferPointer { signature in
            message.withUnsafeBufferPointer { msg in
                buffer.withUnsafeBufferPointer { pub in
                    ed25519_verify(signature.baseAddress,
                                   msg.baseAddress,
                                   message.count,
                                   pub.baseAddress) == 1
                }
            }
        }
    }

    public func add(scalar: [UInt8]) throws -> PublicKey {
        guard scalar.count == 32 else {
            throw Ed25519Error.invalidScalarLength
        }
        
        var pub = buffer
        
        pub.withUnsafeMutableBufferPointer { pub in
            scalar.withUnsafeBufferPointer { scalar in
                ed25519_add_scalar(pub.baseAddress,
                                   nil,
                                   scalar.baseAddress)
            }
        }
        
        return PublicKey(unchecked: pub)
    }
    
    public static func derivePublicKey(bytes: [UInt8]) -> [UInt8] {
        var secretBytes = bytes
        var pubBytes = [UInt8](repeating: 0, count: 32)
        
        secretBytes.withUnsafeMutableBufferPointer { priv in
            pubBytes.withUnsafeMutableBufferPointer { pub in
                ed25519_extract_public_key(pub.baseAddress, priv.baseAddress)
            }
        }
        
        return pubBytes
    }
}
