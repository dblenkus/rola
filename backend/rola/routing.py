from channels.routing import ChannelNameRouter, ProtocolTypeRouter

from rolca.backup.consumers import BackupConsumer
from rolca.backup.protocol import CHANNEL_BACKUP

application = ProtocolTypeRouter(
    {
        # Background worker consumers.
        'channel': ChannelNameRouter({CHANNEL_BACKUP: BackupConsumer}),
    }
)
