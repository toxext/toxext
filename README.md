# ToxExt - An extension library for tox

## Motivation

Tox provides a reasonable base set of features, but new features are slow to implement, and may not be wanted by all clients. This is reasonable as any protocol changes are API breaking and force clients to update to use them. Once the features are in they are there forever meaning quality of the API _and_ the network layer have to be very strong.

An extension library with negotiation allows more experimentation with less risk resulting in more features for tox clients.

## Design

The ToxExt library was designed with the following desires

* Negotiation of extensions
	* Clients should be able to optionally support any extension, which means we need a solid base of negotiation between clients
* Composablity
	* Many extensions should be able to play nicely together
* Ease of use
	* Extensions should be usable wherever tox is usable in a way that is least disruptive to clients
* Future proof
	* The library should be upgradable in a recoverable way

For more implementation details please see DESIGN.md

## Usage

The intent of this library is not to be used directly by clients. Instead we should make extension libraries. In a way that makes ToxExt an extension library library. For some proof of concept examples please see https://github.com/toxext/tox_extension_messages, https://github.com/toxext/tox_extension_sender_timestamp, and https://github.com/sphaerophoria/qTox/tree/extension_poc

Here we create some extensions that provide a couple independent features.

Under the hood each of these extensions doesn't do much, they just register their extension UUID with ToxExt, a couple handlers, and a serialization function.

1. tox_extension_messages
	* This extension re-implements messaging. This unfortunately is necessary as ordering does not seem to be guaranteed by the spec between custom packets and messages.
	* This extension also provides ability for multi-packet messages
1. tox_extension_sender_timestamp
	* This extension tags the message sent by tox_extension_messages with a timestamp

In a client we then just have the following

### Add toxext as a dependency

```
find_package(ToxExt           REQUIRED)
find_package(ToxExtensionMessages           REQUIRED)
find_package(ToxExtensionSenderTimestamp           REQUIRED)

target_link_libraries(target ToxExt::ToxExt ToxExtensionMessages::ToxExtensionMessages ...)
```

### Register supported extensions
```
    toxExtMessages = ExtensionPtr<ToxExtensionMessages>(
        tox_extension_messages_register(
            toxExt.get(),
            CoreExt::onExtendedMessageReceived,
            CoreExt::onExtendedMessageReceipt,
            CoreExt::onExtendedMessageNegotiation,
            this),
        tox_extension_messages_free);

    toxExtSenderTimestamp = ExtensionPtr<ToxExtensionSenderTimestamp>(
        tox_extension_sender_timestamp_register(
            toxExt.get(),
            CoreExt::onSenderTimestampReceived,
            CoreExt::onSenderTimestampNegotiation,
            this),
        tox_extension_sender_timestamp_free);
	...

    void CoreExt::onExtendedMessageReceived(uint32_t friendId, const uint8_t* data, size_t size, void* userData)
    {
        QString msg = ToxString(data, size).getQString();
        emit static_cast<CoreExt*>(userData)->extendedMessageReceived(friendId, msg);
    }

    void CoreExt::onExtendedMessageReceipt(uint32_t friendId, uint64_t receiptId, void* userData)
    {
        emit static_cast<CoreExt*>(userData)->extendedReceiptReceived(friendId, receiptId);
    }

    void CoreExt::onExtendedMessageNegotiation(uint32_t friendId, bool compatible, void* userData)
    {
        auto coreExt = static_cast<CoreExt*>(userData);
        coreExt->extensionSupport[friendId][ExtensionType::messages] = compatible;
    }

    void CoreExt::onSenderTimestampReceived(uint32_t friendId, uint64_t timestamp, void* userData)
    {
        // parse and emit something here
        auto senderTime = QDateTime::fromSecsSinceEpoch(timestamp, QTimeZone::utc());
        emit static_cast<CoreExt*>(userData)->senderTimestampReceived(friendId, senderTime);
    }

    void CoreExt::onSenderTimestampNegotiation(uint32_t friendId, bool compatible, void* userData)
    {
        auto coreExt = static_cast<CoreExt*>(userData);
        coreExt->extensionSupport[friendId][ExtensionType::senderTimestamp] = compatible;
    }
```

### Hookup the custom packet callback to the ToxExt library (in case clients have other custom packets to process)
```
    tox_callback_friend_lossless_packet(tox, onLosslessPacket);
	...
    void Core::onLosslessPacket(Tox* tox, uint32_t friendId,
                                const uint8_t* data, size_t length, void* vCore)
    {
        Core* core = static_cast<Core*>(vCore);
        core->ext->onLosslessPacket(friendId, data, length);
    }
    ...
    void CoreExt::onLosslessPacket(uint32_t friendId, const uint8_t* data, size_t length)
    {
        if (is_toxext_packet(data, length)) {
            toxext_handle_lossless_custom_packet(toxExt.get(), friendId, data, length);
        }
    }
```

### Negotiate with friends when they come online
```
    void CoreExt::onFriendStatusChanged(uint32_t friendId, Status::Status status)
    {
        if (status != Status::Status::Offline) {
            tox_extension_messages_negotiate(toxExtMessages.get(), friendId);
            tox_extension_sender_timestamp_negotiate(toxExtSenderTimestamp.get(), friendId);
        }
        else {
            extensionSupport[friendId] = 0;
        }
    }
```

### And then send the new extension packets to your friends if they support them
```

    // Action messages go over the regular mesage channel so we cannot use extensions with them
    if (supportedExtensions.any() && !isAction) {
        auto packet = coreExt.getPacketBuilder(f.getId());

        if (supportedExtensions[ExtensionType::senderTimestamp]) {
            packet.addSenderTimestamp(message.timestamp);
        }

        // NOTE: extended message needs to come last since other extensions reference the upcoming message
        if (supportedExtensions[ExtensionType::messages]) {
            receipt.get() = packet.addExtendedMessage(message.content);
        }

        messageSent = coreExt.send(std::move(packet));
    } else {
        messageSent = sendMessageToCore(messageSender, f, message, receipt);
    }
```

Pretty straight forward to use from a client perspective. Implementation of extensions is fairly simple too, not much more than parsing of their own custom data.

## Caveats

The big caveat here is that we do not have support for custom packets in groups. This means that any features implemented with extensions can _only_ be used between friends

## Testing

We provide a Mock library you can use by linking ToxExt::Mock. This provides some test fixtures at toxext/mock_fixtures.h and a mock tox implementation. See tox_extension_messages for a test example
